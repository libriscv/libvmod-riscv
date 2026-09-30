#include "vcl_program.hpp"
#include "compiler.hpp"
#include "vcl_varnish.h"
#include "../machine_instance.hpp"
#include "../sandbox_tenant.hpp"
#include "../varnish.hpp"
#include <cstring>
#include <libriscv/elf.hpp>
#include <stdexcept>
#include <strings.h>

namespace rvs::vcl {

/* The hooks a compiled policy exports, and the VMOD callback each one
   answers (callback_names in machine_instance.hpp). vcl_synth has no hook:
   the compiler folds it into on_recv and on_deliver. */
static constexpr std::pair<const char*, size_t> HOOKS[] = {
	{"on_recv", 1},              // ON_REQUEST
	{"on_backend_request", 4},   // ON_BACKEND_FETCH
	{"on_backend_response", 5},  // ON_BACKEND_RESPONSE
	{"on_deliver", 7},           // ON_DELIVER
};
/* Carapace's ceiling on the region, kept: a request global is at most 264
   bytes, and the region is copied into every fork. */
static constexpr uint64_t MAX_GLOBALS = 8192;

Program::~Program()
{
	for (auto& [pattern, re] : patterns)
		vclv_regex_free(re);
}

const void* Program::pattern(std::string_view pattern) const
{
	auto it = patterns.find(std::string(pattern));
	return it != patterns.end() ? it->second : nullptr;
}

std::unique_ptr<Program> Program::install(Script& master, MachineInstance& inst)
{
	auto program = std::make_unique<Program>();
	auto& machine = master.machine();
	const auto& binary = inst.binary;
	/* A section's bytes, or null when it is absent. Every offset is
	   checked: the loader has accepted the ELF, but these sections are not
	   loaded, so nothing else has looked at them. */
	auto section = [&] (const char* name, size_t& size) -> const uint8_t* {
		using Elf = riscv::Elf<8>;
		auto fits = [&] (uint64_t off, uint64_t len) {
			return off <= binary.size() && len <= binary.size() - off;
		};
		Elf::Header hdr;
		if (!fits(0, sizeof(hdr)))
			return nullptr;
		memcpy(&hdr, binary.data(), sizeof(hdr));
		if (hdr.e_shentsize != sizeof(Elf::SectionHeader) || hdr.e_shstrndx >= hdr.e_shnum
			|| !fits(hdr.e_shoff, uint64_t(hdr.e_shnum) * sizeof(Elf::SectionHeader)))
			return nullptr;
		auto header = [&] (unsigned i) {
			Elf::SectionHeader sh;
			memcpy(&sh, binary.data() + hdr.e_shoff + i * sizeof(sh), sizeof(sh));
			return sh;
		};
		const auto strtab = header(hdr.e_shstrndx);
		if (!fits(strtab.sh_offset, strtab.sh_size))
			return nullptr;
		const size_t name_len = strlen(name) + 1;
		for (unsigned i = 0; i < hdr.e_shnum; i++) {
			const auto sh = header(i);
			if (sh.sh_name >= strtab.sh_size || strtab.sh_size - sh.sh_name < name_len
				|| memcmp(binary.data() + strtab.sh_offset + sh.sh_name, name, name_len) != 0)
				continue;
			if (!fits(sh.sh_offset, sh.sh_size))
				throw std::runtime_error(std::string("VCL program: ") + name + " lies outside the ELF");
			size = sh.sh_size;
			return binary.data() + sh.sh_offset;
		}
		return nullptr;
	};

	/* NUL-separated pattern literals. */
	size_t size = 0;
	if (const auto* bytes = section(".carapace.regex", size)) {
		const char* p = reinterpret_cast<const char*>(bytes);
		const char* end = p + size;
		while (p < end) {
			const char* nul = static_cast<const char*>(memchr(p, '\0', end - p));
			if (nul == nullptr)
				throw std::runtime_error("VCL program: unterminated pattern in .carapace.regex");
			std::string pattern(p, nul);
			p = nul + 1;
			if (program->patterns.count(pattern))
				continue;
			const char* error = "";
			void* re = vclv_regex_compile(pattern.c_str(), &error);
			if (re == nullptr)
				throw std::runtime_error("VCL program: regex '" + pattern + "' does not compile: " + error);
			program->patterns.emplace(std::move(pattern), re);
		}
	}

	/* address, size, then the initial image. */
	if (const auto* p = section(".carapace.globals", size)) {
		const size_t section_size = size;
		if (section_size < 16)
			throw std::runtime_error("VCL program: .carapace.globals is truncated");
		uint64_t address;
		memcpy(&address, p, 8);
		memcpy(&size, p + 8, 8);
		if (size == 0 || size > MAX_GLOBALS || section_size != 16 + size)
			throw std::runtime_error("VCL program: .carapace.globals has a bad size");
		program->globals_address = address;
		program->globals_image.assign(p + 16, p + 16 + size);
		/* Every fork starts from the master, so seeding it once is what
		   gives each request its own copy of the initial values. */
		machine.copy_to_guest(address, program->globals_image.data(), size);
	}

	for (auto& [symbol, index] : HOOKS)
		inst.callback_entries.at(index) = machine.address_of(symbol);
	return program;
}

/* ── Staged synthetic response ──────────────────────────────────────── */

static bool same_name(std::string_view a, std::string_view b)
{
	return a.size() == b.size() && strncasecmp(a.data(), b.data(), a.size()) == 0;
}

const std::string* StagedSynth::get(std::string_view name) const
{
	for (auto& [n, v] : headers)
		if (same_name(n, name)) return &v;
	return nullptr;
}

void StagedSynth::set(std::string_view name, std::string_view value)
{
	unset(name);
	add(name, value);
}

void StagedSynth::add(std::string_view name, std::string_view value)
{
	headers.emplace_back(std::string(name), std::string(value));
}

void StagedSynth::unset(std::string_view name)
{
	std::erase_if(headers, [&](auto& h) { return same_name(h.first, name); });
	for (auto& r : removed)
		if (same_name(r, name)) return;
	removed.emplace_back(name);
}

void apply_synth(Script& script)
{
	auto& synth = script.vcl_task().synth;
	const auto* ctx = script.ctx();
	if (!synth.active || vclv_phase(ctx) != VCL_PHASE_SYNTH)
		return;
	auto* hp = vclv_http(ctx, VCL_SIDE_RESPONSE);
	if (hp == nullptr)
		return;
	/* Varnish's synthetic response starts with defaults of its own. A name
	   the policy removed or set replaces them; the rest stay. */
	for (auto& name : synth.removed)
		vclv_unset(hp, name.data(), name.size());
	for (auto& [name, value] : synth.headers)
		vclv_unset(hp, name.data(), name.size());
	for (auto& [name, value] : synth.headers)
		vclv_add(ctx, hp, name.data(), name.size(), value.data(), value.size());
	vclv_set_reason(ctx, synth.reason.data(), synth.reason.size());
	vclv_synth_body(ctx, synth.body.data(), synth.body.size());
	synth = StagedSynth{};
}

bool is_vcl_source(std::string_view filename)
{
	return filename.size() > 4 && filename.substr(filename.size() - 4) == ".vcl";
}

std::shared_ptr<MachineInstance> load(const std::string& path,
	const vrt_ctx* ctx, SandboxTenant* tenant)
{
	auto compiled = compile(path);
	for (auto& warning : compiled.warnings) {
		VSL(SLT_VCL_Log, 0, "[%s] VCL warning: %s",
			tenant->config.name.c_str(), warning.c_str());
		printf("[%s] VCL warning: %s\n", tenant->config.name.c_str(), warning.c_str());
	}
	return std::make_shared<MachineInstance>(std::move(compiled.elf), ctx, tenant, false, true);
}

} // rvs::vcl
