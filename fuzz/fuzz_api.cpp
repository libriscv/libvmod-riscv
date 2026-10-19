/* libFuzzer harness for the tenant scripting API (src/script_functions.cpp).

   Every input boots a fresh tenant from the embedded guest program
   (guest.cpp), then runs one or more tasks the way Varnish does: fork the
   tenant into a request VM, let the guest make system calls, deliver the
   result and throw the fork away. The guest's side of each system call,
   the argument registers and the memory they point at, comes from the
   input. Everything is rebuilt per input, so any crash reproduces from
   its input alone.

   Besides ASan and UBSan, the harness checks the HTTP objects after every
   call, and the SHA-256 system call against a reference digest. */
#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/sha.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include "fake_varnish.h"
#include "machine_instance.hpp"
#include "sandbox_tenant.hpp"
#include "varnish.hpp"
extern "C" {
#include "varnish_interface.h"
}
#include "machine/syscalls.h"

using namespace rvs;
using gaddr_t = Script::gaddr_t;

/* The VCL syscalls need the whole of vcl_varnish.c, and are not part of
   the scripting API. */
namespace rvs::vcl { void install_syscalls() {} }

extern "C" const char fuzz_guest_elf[];
extern "C" const char fuzz_guest_elf_end[];
asm(".section .rodata\n"
	".global fuzz_guest_elf\n"
	"fuzz_guest_elf:\n"
	".incbin \"" FUZZ_GUEST_ELF "\"\n"
	".global fuzz_guest_elf_end\n"
	"fuzz_guest_elf_end:\n"
	".previous\n");

static constexpr unsigned NUM_SYSCALLS = ECALL_LAST - SYSCALL_BASE;
static constexpr size_t   MAX_TASKS = 4;
static constexpr size_t   MAX_OPS   = 48;
static constexpr size_t   WORKSPACE = 64 * 1024;

static std::vector<uint8_t> guest_binary;
static TenantGroup tenant_group;

/* Guest symbols that pointer arguments are drawn from */
struct GuestLayout {
	gaddr_t scratch;
	size_t  scratch_size;
	gaddr_t functions[4];
	gaddr_t text;
	gaddr_t stack;
	gaddr_t heap;
};

struct Http {
	struct http hp {};
	std::unique_ptr<txt[]> fields;
	std::unique_ptr<unsigned char[]> flags;
};

/* One Varnish task (a client request or a backend fetch) */
struct Task {
	struct ws* ws = nullptr;
	struct vrt_ctx ctx {};
	fake::req req;
	fake::busyobj bo;
	Http https[4]; /* req, resp, bereq, beresp */
	struct vsb* synth_body = nullptr;

	~Task() {
		if (synth_body != nullptr) {
			if (synth_body->s_flags & VSB_DYNAMIC)
				free(synth_body->s_buf);
			delete synth_body;
		}
		fake::forget_snapshots();
		if (ws != nullptr)
			fake::ws_delete(ws);
	}
};

static const char* ws_string(struct ws* ws, const std::string& str)
{
	return (const char *)WS_Copy(ws, str.c_str(), str.size() + 1);
}

static void setup_http(Task& task, Http& h, FuzzedDataProvider& fdp,
	const char* first_line[3])
{
	const uint16_t max = fdp.ConsumeIntegralInRange<uint16_t>(HDR_FIRST + 1, 64);
	h.fields.reset(new txt[max]{});
	h.flags.reset(new unsigned char[max]{});
	h.hp.magic = HTTP_MAGIC;
	h.hp.shd = max;
	h.hp.hd = h.fields.get();
	h.hp.hdf = h.flags.get();
	h.hp.ws = task.ws;
	h.hp.status = 200;
	h.hp.nhd = HDR_FIRST;
	for (int i = 0; i < 3; i++) {
		if (first_line[i] == nullptr)
			continue;
		const char* s = ws_string(task.ws, first_line[i]);
		h.fields[i] = {s, s + strlen(s)};
	}
	static const char* defaults[] = {
		"Host: fuzz.tenant", "Accept: */*", "Cookie: a=1; b=2", "X-Forwarded-For: 127.0.0.1"};
	for (const char* d : defaults) {
		if (h.hp.nhd >= max)
			break;
		const char* s = ws_string(task.ws, d);
		h.fields[h.hp.nhd++] = {s, s + strlen(s)};
	}
	/* Fuzzed header fields; Varnish never has a NUL inside one */
	const unsigned extra = fdp.ConsumeIntegralInRange<unsigned>(0, 4);
	for (unsigned i = 0; i < extra && h.hp.nhd < max; i++) {
		std::string str = fdp.ConsumeRandomLengthString(96);
		str.erase(std::remove(str.begin(), str.end(), '\0'), str.end());
		const char* s = ws_string(task.ws, str);
		if (s == nullptr)
			break;
		h.fields[h.hp.nhd++] = {s, s + str.size()};
	}
}

static void setup_task(Task& task, FuzzedDataProvider& fdp)
{
	static const unsigned methods[] = {
		VCL_MET_RECV, VCL_MET_HASH, VCL_MET_DELIVER, VCL_MET_SYNTH,
		VCL_MET_BACKEND_FETCH, VCL_MET_BACKEND_RESPONSE, VCL_MET_BACKEND_ERROR};
	const unsigned method = fdp.PickValueInArray(methods);
	const bool client = method == VCL_MET_RECV || method == VCL_MET_HASH
		|| method == VCL_MET_DELIVER || method == VCL_MET_SYNTH;

	task.ws = fake::ws_new(WORKSPACE);
	auto& ctx = task.ctx;
	ctx.magic = VRT_CTX_MAGIC;
	ctx.method = method;
	ctx.ws = task.ws;
	const char* req_line[3] = {"GET", "/index.html?q=1", "HTTP/1.1"};
	const char* resp_line[3] = {nullptr, nullptr, "HTTP/1.1"};
	if (client) {
		ctx.req = (struct req *)&task.req;
		setup_http(task, task.https[0], fdp, req_line);
		ctx.http_req = &task.https[0].hp;
		ctx.http_req_top = ctx.http_req;
		if (method == VCL_MET_DELIVER || method == VCL_MET_SYNTH) {
			setup_http(task, task.https[1], fdp, resp_line);
			ctx.http_resp = &task.https[1].hp;
		}
	} else {
		ctx.bo = (struct busyobj *)&task.bo;
		setup_http(task, task.https[2], fdp, req_line);
		ctx.http_bereq = &task.https[2].hp;
		if (method != VCL_MET_BACKEND_FETCH) {
			setup_http(task, task.https[3], fdp, resp_line);
			ctx.http_beresp = &task.https[3].hp;
		}
	}
	if (method == VCL_MET_SYNTH || method == VCL_MET_BACKEND_ERROR) {
		/* VSB_new_auto() */
		task.synth_body = new struct vsb {};
		task.synth_body->magic = VSB_MAGIC;
		task.synth_body->s_size = 64;
		task.synth_body->s_buf = (char *)malloc(64);
		task.synth_body->s_flags = VSB_AUTOEXTEND | VSB_DYNAMIC;
		ctx.specific = task.synth_body;
	}
	fake::snapshot_http(&ctx);
}

/* Known leak: the master VM's page fault handler in Script::machine_setup()
   hands `new PageData` to Page(attr, PageData*), which marks the page
   non-owning, so the pages outlive their MachineInstance. Hand them back
   before teardown, or every input leaks a few pages. */
static void own_master_pages(Script& script)
{
	for (auto& it : script.machine().memory.pages()) {
		auto& page = it.second;
		if (page.attr.user_defined == 1 && page.attr.non_owning)
			page.attr.non_owning = false;
	}
}

static gaddr_t pick_arg(FuzzedDataProvider& fdp, const GuestLayout& g)
{
	switch (fdp.ConsumeIntegralInRange<int>(0, 8)) {
	case 0: /* where, booleans, small handles */
		return fdp.ConsumeIntegralInRange<gaddr_t>(0, 7);
	case 1: /* header field index */
		return fdp.ConsumeIntegralInRange<gaddr_t>(0, 70);
	case 2: {
		static const gaddr_t special[] = {
			0, ~gaddr_t(0), HDR_INVALID, 0x80000000, 0x7FFFFFFF, 0x7FFFFFFE,
			0xFFFF, 0x10000, 4095, 4096, 4097, 1u << 20, 1000, 1099, 99, 32};
		return fdp.PickValueInArray(special);
	}
	case 3: /* inside the scratch buffer */
		return g.scratch + fdp.ConsumeIntegralInRange<size_t>(0, g.scratch_size - 1);
	case 4: /* just below a page boundary inside scratch */
		return g.scratch + 4096 * fdp.ConsumeIntegralInRange<int>(1, 2)
			- fdp.ConsumeIntegralInRange<int>(0, 64);
	case 5: /* length */
		return fdp.ConsumeIntegralInRange<gaddr_t>(0, 0x2000);
	case 6:
		return fdp.PickValueInArray(g.functions);
	case 7: {
		const gaddr_t bases[] = {g.text, g.stack, g.heap, 0x10000, 0xFFFFFFFFFFFF0000ull};
		return fdp.PickValueInArray(bases) + fdp.ConsumeIntegralInRange<gaddr_t>(0, 0x1000);
	}
	default:
		return fdp.ConsumeIntegral<gaddr_t>();
	}
}

/* The reference digest for ECALL_SHA256, taken before the call
   since the destination may overlap the source. */
struct Sha256Check {
	bool armed = false;
	gaddr_t dst = 0;
	unsigned char expected[32];
};

static Sha256Check prepare_sha256(Script::machine_t& m)
{
	Sha256Check check;
	const auto& regs = m.cpu.registers();
	const gaddr_t src = regs.get(10), len = regs.get(11);
	if (regs.get(13) != 32 || len > 0x10000)
		return check;
	std::vector<uint8_t> data(len);
	try {
		m.memory.memcpy_out(data.data(), src, len);
	} catch (...) {
		return check;
	}
	SHA256(data.data(), data.size(), check.expected);
	check.dst = regs.get(12);
	check.armed = true;
	return check;
}

static void verify_sha256(Script::machine_t& m, const Sha256Check& check)
{
	if (!check.armed || m.return_value<long>() != 32)
		return;
	unsigned char result[32];
	m.memory.memcpy_out(result, check.dst, sizeof(result));
	if (memcmp(result, check.expected, sizeof(result)) != 0) {
		fprintf(stderr, "ECALL_SHA256 returned the wrong digest\n");
		abort();
	}
}

static void check_https(const Task& task)
{
	volatile uint32_t sum = 0;
	for (auto* hp : {task.ctx.http_req, task.ctx.http_resp,
			task.ctx.http_bereq, task.ctx.http_beresp}) {
		if (hp != nullptr)
			sum += fake::touch_http(hp);
	}
}

static void system_call(Script& script, FuzzedDataProvider& fdp, const GuestLayout& g)
{
	auto& m = script.machine();
	const unsigned idx = fdp.ConsumeIntegralInRange<unsigned>(0, NUM_SYSCALLS - 1);
	for (int r = 0; r < 7; r++)
		m.cpu.reg(10 + r) = pick_arg(fdp, g);
	m.cpu.reg(17) = SYSCALL_BASE + idx;

	Sha256Check sha;
	if (SYSCALL_BASE + idx == ECALL_SHA256) {
		sha = prepare_sha256(m);
	}

	/* Each call is a fresh vcall into the VM, as in Script::call() */
	m.reset_instruction_counter();
	m.set_max_instructions(script.max_instructions());
	try {
		/* FUZZ_TRACE=1 names each call and its cost, to find a slow input's culprit */
		static const bool trace = getenv("FUZZ_TRACE") != nullptr;
		const auto t0 = std::chrono::steady_clock::now();
		m.system_call(SYSCALL_BASE + idx);
		if (trace) {
			const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now() - t0).count();
			fprintf(stderr, "TRACE syscall %u (a0=%#lx a1=%#lx a2=%#lx a3=%#lx): %ld us\n",
				SYSCALL_BASE + idx, (long)m.cpu.reg(10), (long)m.cpu.reg(11),
				(long)m.cpu.reg(12), (long)m.cpu.reg(13), (long)us);
		}
		verify_sha256(m, sha);
	} catch (const std::exception&) {
		/* The guest is terminated, and the VCL fails */
		VRT_fail(script.ctx(), "exception");
	}
}

static void write_scratch(Script& script, FuzzedDataProvider& fdp, const GuestLayout& g)
{
	const size_t off = fdp.ConsumeIntegralInRange<size_t>(0, g.scratch_size - 1);
	const size_t len = fdp.ConsumeIntegralInRange<size_t>(0,
		std::min<size_t>(512, g.scratch_size - off));
	const auto bytes = fdp.ConsumeBytes<uint8_t>(len);
	try {
		script.machine().copy_to_guest(g.scratch + off, bytes.data(), bytes.size());
	} catch (const std::exception&) {
		/* The guest may have made its scratch memory read-only */
	}
}

/* What Varnish does with a synth body after vcl_synth/vcl_backend_error */
static void deliver_synth(Task& task)
{
	struct vsb* vsb = task.synth_body;
	if (vsb == nullptr)
		return;
	/* VSB_finish() */
	vsb->s_buf[vsb->s_len] = '\0';
	volatile unsigned char sum = 0;
	for (ssize_t i = 0; i < vsb->s_len; i++)
		sum += vsb->s_buf[i];
}

static void run_task(SandboxTenant& tenant, std::shared_ptr<MachineInstance>& prog,
	const GuestLayout& g, FuzzedDataProvider& fdp)
{
	Task task;
	setup_task(task, fdp);

	/* SandboxTenant::vmfork() */
	void* mem = aligned_alloc(32, (sizeof(Script) + 31) & ~size_t(31));
	Script* script;
	try {
		script = new (mem) Script{prog->script, &task.ctx, &tenant, *prog};
	} catch (const std::exception& e) {
		VRT_fail(&task.ctx, "VM exception: %s", e.what());
		free(mem);
		return;
	}
	auto ref = prog;
	script->assign_instance(ref);

	const size_t ops = fdp.ConsumeIntegralInRange<size_t>(1, MAX_OPS);
	for (size_t i = 0; i < ops && fdp.remaining_bytes() > 0; i++) {
		if (fdp.ConsumeIntegralInRange<int>(0, 3) == 0)
			write_scratch(*script, fdp, g);
		else
			system_call(*script, fdp, g);
		check_https(task);
	}
	deliver_synth(task);
	check_https(task);

	script->~Script();
	free(mem);
}

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
	guest_binary.assign(fuzz_guest_elf, fuzz_guest_elf_end);
	tenant_group.max_instructions = 200'000;
	tenant_group.max_memory_mb = 16;
	tenant_group.max_regex = 8;
	tenant_group.max_backends = 4;
	SandboxTenant::init();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	FuzzedDataProvider fdp(data, size);
	fake::vrt_failures = 0;

	/* vcl_init: the master VM and its storage VM */
	struct ws* init_ws = fake::ws_new(WORKSPACE);
	struct vrt_ctx init_ctx {};
	init_ctx.magic = VRT_CTX_MAGIC;
	init_ctx.method = VCL_MET_INIT;
	init_ctx.ws = init_ws;

	{
		SandboxTenant tenant(&init_ctx, TenantConfig{"fuzz.tenant", "guest", tenant_group});
		auto prog = std::make_shared<MachineInstance>(guest_binary, &init_ctx, &tenant);
		tenant.program = prog;

		const auto& script = prog->script;
		GuestLayout g;
		g.scratch = script.resolve_address("fuzz_scratch");
		g.scratch_size = 3 * 4096;
		g.functions[0] = script.resolve_address("fuzz_foreach");
		g.functions[1] = script.resolve_address("fuzz_return");
		g.functions[2] = script.resolve_address("fuzz_spin");
		g.functions[3] = 0;
		g.text = script.machine().memory.start_address();
		g.stack = script.stack_begin() - 0x2000;
		g.heap = script.machine().memory.heap_address();
		if (g.scratch == 0 || g.functions[0] == 0) {
			fprintf(stderr, "The guest program is missing its fuzzing symbols\n");
			abort();
		}

		const size_t tasks = fdp.ConsumeIntegralInRange<size_t>(1, MAX_TASKS);
		for (size_t t = 0; t < tasks && fdp.remaining_bytes() > 0; t++)
			run_task(tenant, prog, g, fdp);

		own_master_pages(prog->script);
		own_master_pages(prog->storage);
		tenant.program = nullptr;
	}
	fake::ws_delete(init_ws);
	return 0;
}
