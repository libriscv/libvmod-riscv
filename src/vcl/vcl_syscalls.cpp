/**
 * The policy ABI (abi.hpp) that VCL-compiled tenant programs call.
 *
 * Ported from Carapace's scripting host, with one structural difference:
 * Carapace records a phase's header edits and replays them afterwards,
 * while here the phase runs inside Varnish's own VCL subroutine, so edits
 * go straight to Varnish's header maps. The one exception is a synthetic
 * response, which is staged until vcl_synth (vcl_program.hpp).
 *
 * The compiler already refuses what a phase may not do, with a source
 * diagnostic. Every gate is checked again here, because the compiled ELF is
 * the tenant's and the host trusts nothing about it.
 */
#include "abi.hpp"
#include "vcl_program.hpp"
#include "vcl_varnish.h"
#include "../script_functions.hpp"
#include "../machine_instance.hpp"
#include "../varnish.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace rvs::vcl {
using namespace abi;

/* The compiler guest's include read, installed by compiler.cpp. */
void include_read(machine_t&);

namespace {

/* Headers a policy never writes: they describe the message framing, which
   Varnish owns. Mirrors FRAMING_HEADERS in vcl/compiler/src/vcl_vars.def. */
constexpr std::string_view FRAMING_HEADERS[] = {
	"connection", "content-length", "keep-alive", "proxy-authenticate",
	"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
};

bool iequals(std::string_view a, std::string_view b)
{
	return a.size() == b.size() && strncasecmp(a.data(), b.data(), a.size()) == 0;
}

bool is_framing_header(std::string_view name)
{
	for (auto framing : FRAMING_HEADERS)
		if (iequals(name, framing)) return true;
	return false;
}

/* An RFC 9110 token: what a header name may be. */
bool valid_name(std::string_view name)
{
	if (name.empty())
		return false;
	for (unsigned char c : name) {
		if (isalnum(c))
			continue;
		if (!strchr("!#$%&'*+-.^_`|~", c) || c == '\0')
			return false;
	}
	return true;
}

/* A header value or URL must not end the line it is on: a CR or LF would
   let a tenant add header fields, or a whole request, of its own. */
bool valid_value(std::string_view value)
{
	return value.find_first_of(std::string_view("\r\n\0", 3)) == std::string_view::npos;
}

Script& script_of(machine_t& m) { return *m.get_userdata<Script>(); }
const vrt_ctx* ctx_of(machine_t& m) { return script_of(m).ctx(); }

/* Copy a guest (pointer, length) string out, or fail on a length past max.
   Copying rather than viewing: a fork's pages come from the workspace one
   at a time, so a string crossing a page boundary is not contiguous. */
bool read_str(machine_t& m, gaddr_t addr, gaddr_t len, size_t max, std::string& out)
{
	if (len > max)
		return false;
	out.resize(len);
	if (len > 0)
		m.memory.memcpy_out(out.data(), addr, len);
	m.penalize(len);
	return true;
}

/* Write a result into a guest buffer, truncated to the buffer. Returns the
   full length, so a caller that measured with a null buffer learns it. */
uint64_t write_str(machine_t& m, gaddr_t buf, gaddr_t buflen, std::string_view data)
{
	if (buf != 0 && buflen != 0) {
		const size_t n = std::min<size_t>(data.size(), buflen);
		if (n > 0)
			m.copy_to_guest(buf, data.data(), n);
		m.penalize(n);
	}
	return data.size();
}

void refuse(machine_t& m, const char* what)
{
	auto* ctx = ctx_of(m);
	if (ctx && ctx->vsl)
		VSLb(ctx->vsl, SLT_VCL_Error, "[%s] vcl: %s refused in this subroutine",
			script_of(m).name().c_str(), what);
	m.set_result(FAILED);
}

/* Which header map a write goes to, in this phase. */
enum class Target { Refused, Http, Staged };

Target request_target(const vrt_ctx* ctx, http*& hp, bool write)
{
	const auto phase = vclv_phase(ctx);
	if (write && phase != VCL_PHASE_RECV && phase != VCL_PHASE_BACKEND_FETCH)
		return Target::Refused;
	hp = vclv_http(ctx, VCL_SIDE_REQUEST);
	return hp ? Target::Http : Target::Refused;
}

Target response_target(Script& script, const vrt_ctx* ctx, http*& hp)
{
	/* Once a policy has returned synth(...), "resp" is the synthetic
	   response it is building, in vcl_recv and vcl_deliver alike. */
	if (script.vcl_task().synth.active)
		return Target::Staged;
	const auto phase = vclv_phase(ctx);
	if (phase == VCL_PHASE_RECV || phase == VCL_PHASE_BACKEND_FETCH)
		return Target::Refused;
	hp = vclv_http(ctx, VCL_SIDE_RESPONSE);
	return hp ? Target::Http : Target::Refused;
}

/* ── Request line, headers, status ──────────────────────────────────── */

void sys_req_get_method(machine_t& m)
{
	const auto [buf, buflen] = m.sysargs<gaddr_t, gaddr_t>();
	http* hp = nullptr;
	if (request_target(ctx_of(m), hp, false) == Target::Refused) {
		m.set_result(write_str(m, buf, buflen, ""));
		return;
	}
	size_t len;
	const char* method = vclv_method(hp, &len);
	m.set_result(write_str(m, buf, buflen, {method, len}));
}

void sys_req_get_url(machine_t& m)
{
	const auto [buf, buflen] = m.sysargs<gaddr_t, gaddr_t>();
	http* hp = nullptr;
	if (request_target(ctx_of(m), hp, false) == Target::Refused) {
		m.set_result(write_str(m, buf, buflen, ""));
		return;
	}
	size_t len;
	const char* url = vclv_url(hp, &len);
	m.set_result(write_str(m, buf, buflen, {url, len}));
}

void get_header(machine_t& m, bool response)
{
	const auto [nptr, nlen, buf, buflen] = m.sysargs<gaddr_t, gaddr_t, gaddr_t, gaddr_t>();
	std::string name;
	if (!read_str(m, nptr, nlen, MAX_NAME, name)) {
		m.set_result(FAILED);
		return;
	}
	auto& script = script_of(m);
	http* hp = nullptr;
	const auto target = response
		? response_target(script, script.ctx(), hp)
		: request_target(script.ctx(), hp, false);
	if (target == Target::Staged) {
		const auto* value = script.vcl_task().synth.get(name);
		m.set_result(value ? write_str(m, buf, buflen, *value) : FAILED);
		return;
	}
	const char* value;
	size_t vlen;
	if (target == Target::Refused || vclv_get(hp, name.data(), name.size(), &value, &vlen) < 0) {
		m.set_result(FAILED);
		return;
	}
	m.set_result(write_str(m, buf, buflen, {value, vlen}));
}

void set_header(machine_t& m, bool response)
{
	const auto [nptr, nlen, vptr, vlen] = m.sysargs<gaddr_t, gaddr_t, gaddr_t, gaddr_t>();
	std::string name, value;
	if (!read_str(m, nptr, nlen, MAX_NAME, name) || !read_str(m, vptr, vlen, MAX_VALUE, value)
		|| !valid_name(name) || !valid_value(value)) {
		m.set_result(FAILED);
		return;
	}
	if (is_framing_header(name)) {
		refuse(m, "a framing header write");
		return;
	}
	auto& script = script_of(m);
	http* hp = nullptr;
	const auto target = response
		? response_target(script, script.ctx(), hp)
		: request_target(script.ctx(), hp, true);
	switch (target) {
	case Target::Staged:
		script.vcl_task().synth.set(name, value);
		m.set_result(0);
		return;
	case Target::Http:
		m.set_result(vclv_set(script.ctx(), hp, name.data(), name.size(),
			value.data(), value.size()) == 0 ? 0 : FAILED);
		return;
	case Target::Refused:
		refuse(m, response ? "a response header write" : "a request header write");
		return;
	}
}

void remove_header(machine_t& m, bool response)
{
	const auto [cmd, nptr, nlen] = m.sysargs<int64_t, gaddr_t, gaddr_t>();
	(void)cmd;
	std::string name;
	if (!read_str(m, nptr, nlen, MAX_NAME, name) || name.empty()) {
		m.set_result(FAILED);
		return;
	}
	if (is_framing_header(name)) {
		refuse(m, "a framing header removal");
		return;
	}
	auto& script = script_of(m);
	http* hp = nullptr;
	const auto target = response
		? response_target(script, script.ctx(), hp)
		: request_target(script.ctx(), hp, true);
	switch (target) {
	case Target::Staged:
		script.vcl_task().synth.unset(name);
		m.set_result(0);
		return;
	case Target::Http:
		vclv_unset(hp, name.data(), name.size());
		m.set_result(0);
		return;
	case Target::Refused:
		refuse(m, response ? "a response header removal" : "a request header removal");
		return;
	}
}

void sys_req_get_header(machine_t& m)  { get_header(m, false); }
void sys_resp_get_header(machine_t& m) { get_header(m, true); }
void sys_req_set_header(machine_t& m)  { set_header(m, false); }
void sys_resp_set_header(machine_t& m) { set_header(m, true); }

void sys_req_set_url(machine_t& m)
{
	const auto [uptr, ulen] = m.sysargs<gaddr_t, gaddr_t>();
	std::string url;
	if (!read_str(m, uptr, ulen, MAX_VALUE, url) || url.empty() || !valid_value(url)
		|| url.find(' ') != std::string::npos) {
		m.set_result(FAILED);
		return;
	}
	const auto* ctx = ctx_of(m);
	/* bereq.url only: the compiler has no writable req.url. */
	if (vclv_phase(ctx) != VCL_PHASE_BACKEND_FETCH) {
		refuse(m, "a URL write");
		return;
	}
	m.set_result(vclv_set_url(ctx, vclv_http(ctx, VCL_SIDE_REQUEST),
		url.data(), url.size()) == 0 ? 0 : FAILED);
}

void sys_resp_get_status(machine_t& m)
{
	auto& script = script_of(m);
	if (script.vcl_task().synth.active) {
		m.set_result(script.vcl_task().synth.status);
		return;
	}
	auto* hp = vclv_http(script.ctx(), VCL_SIDE_RESPONSE);
	m.set_result(hp ? vclv_status(hp) : 0u);
}

void sys_log(machine_t& m)
{
	const auto [ptr, len] = m.sysargs<gaddr_t, gaddr_t>();
	std::string msg;
	if (!read_str(m, ptr, len, MAX_VALUE, msg)) {
		m.set_result(FAILED);
		return;
	}
	vclv_log(ctx_of(m), msg.data(), msg.size());
	m.set_result(0);
}

/* ── Outcomes ───────────────────────────────────────────────────────── */

/* Record what a hook asked for, as want_result() reports it:
   "" (carry on), "pass", "deliver", "synth" or "abandon". */
void set_outcome(machine_t& m, int64_t code, uint16_t status, gaddr_t body, gaddr_t blen)
{
	auto& script = script_of(m);
	const auto* ctx = script.ctx();
	const auto phase = vclv_phase(ctx);
	switch (code) {
	case ACTION_PASS:
		/* Pass in vcl_backend_response is "do not cache this". */
		if (phase == VCL_PHASE_BACKEND_RESPONSE)
			vclv_set_uncacheable(ctx);
		script.set_result("pass", 0, false);
		return;
	case ACTION_DELIVER:
		script.set_result("deliver", 0, false);
		return;
	case ACTION_ABANDON:
		if (phase == VCL_PHASE_BACKEND_RESPONSE) {
			script.set_result("abandon", 0, false);
			return;
		}
		refuse(m, "abandon");
		script.set_result("", 0, false);
		return;
	case ACTION_SYNTH: {
		/* A deliver synth abandons the response it was about to send, so
		   it is an error path: a 2xx or 3xx would be a body rewrite or a
		   scripted redirect. The compiler refuses the same statuses. */
		const bool allowed = phase == VCL_PHASE_RECV
			|| (phase == VCL_PHASE_DELIVER && status >= 400);
		std::string text;
		if (!allowed || status < 100 || status > 999) {
			refuse(m, "a synthetic response");
			script.set_result("", 0, false);
			return;
		}
		/* A body past the cap is dropped, not truncated. */
		read_str(m, body, blen, MAX_BODY, text);
		auto& synth = script.vcl_task().synth;
		if (!synth.active) {
			/* The transition: a fresh response, with the synth reason as
			   its reason and its default body. Nothing carries over from
			   the response a deliver synth replaces. */
			synth = StagedSynth{};
			synth.active = true;
			synth.reason = text;
		}
		synth.status = status;
		synth.body = std::move(text);
		script.set_result("synth", status, false);
		return;
	}
	case ACTION_NEXT:
	default:
		script.set_result("", 0, false);
		return;
	}
}

void sys_return_action(machine_t& m)
{
	const auto [code, status, body, blen] = m.sysargs<int64_t, uint64_t, gaddr_t, gaddr_t>();
	set_outcome(m, code, uint16_t(std::min<uint64_t>(status, UINT16_MAX)), body, blen);
	m.stop();
}

void sys_set_outcome_plain(machine_t& m)
{
	const auto [cmd, code, status, body, blen] =
		m.sysargs<int64_t, int64_t, uint64_t, gaddr_t, gaddr_t>();
	(void)cmd;
	set_outcome(m, code, uint16_t(std::min<uint64_t>(status, UINT16_MAX)), body, blen);
	m.set_result(0);
}

/* ── Cache metadata ─────────────────────────────────────────────────── */

bool valid_seconds(uint64_t raw)
{
	return int64_t(raw) >= 0 && raw <= MAX_TTL_SECONDS;
}

void set_duration(machine_t& m, vcl_duration which, uint64_t seconds)
{
	const auto* ctx = ctx_of(m);
	if (vclv_phase(ctx) != VCL_PHASE_BACKEND_RESPONSE) {
		refuse(m, "a cache duration write");
		return;
	}
	if (!valid_seconds(seconds)) {
		m.set_result(FAILED);
		return;
	}
	vclv_set_duration(ctx, which, double(seconds));
	m.set_result(0);
}

void sys_set_ttl(machine_t& m)
{
	set_duration(m, VCL_TTL, m.sysarg<uint64_t>(0));
}

void sys_cache_duration(machine_t& m)
{
	const auto selector = m.sysarg<uint64_t>(1);
	const auto* ctx = ctx_of(m);
	if (vclv_phase(ctx) != VCL_PHASE_BACKEND_RESPONSE) {
		refuse(m, "a cache duration read");
		return;
	}
	if (selector > VCL_KEEP) {
		m.set_result(FAILED);
		return;
	}
	const double value = vclv_get_duration(ctx, vcl_duration(selector));
	/* Whole seconds, like the setter: a negative TTL reads as 0. */
	m.set_result(uint64_t(std::clamp(value, 0.0, double(MAX_TTL_SECONDS))));
}

void sys_cache_status(machine_t& m)
{
	const int status = vclv_cache_status(ctx_of(m));
	if (status < 0) {
		refuse(m, "a cache status read");
		return;
	}
	m.set_result(uint64_t(status));
}

void sys_client_ip(machine_t& m)
{
	const auto out_ptr = m.sysarg<gaddr_t>(1);
	const auto out_cap = m.sysarg<gaddr_t>(2);
	unsigned char octets[16];
	const int family = vclv_client_ip(ctx_of(m), octets);
	if (family < 0 || out_ptr == 0 || out_cap < sizeof(octets)) {
		m.set_result(FAILED);
		return;
	}
	m.copy_to_guest(out_ptr, octets, sizeof(octets));
	m.set_result(uint64_t(family));
}

/* ── Header snapshots and commits (the headerplus vmod) ─────────────── */

/* The header list a side holds now, as (name, value) pairs. */
std::vector<std::pair<std::string_view, std::string_view>>
header_list(Script& script, bool response, Target& target, http*& hp)
{
	std::vector<std::pair<std::string_view, std::string_view>> out;
	target = response
		? response_target(script, script.ctx(), hp)
		: request_target(script.ctx(), hp, false);
	if (target == Target::Staged) {
		for (auto& [name, value] : script.vcl_task().synth.headers)
			out.emplace_back(name, value);
	} else if (target == Target::Http) {
		unsigned cursor = 0;
		const char *name, *value;
		size_t nlen, vlen;
		while (vclv_next(hp, &cursor, &name, &nlen, &value, &vlen) == 0)
			out.emplace_back(std::string_view{name, nlen}, std::string_view{value, vlen});
	}
	return out;
}

void put_u32(std::string& out, uint32_t v)
{
	out.append(reinterpret_cast<const char*>(&v), 4); // little-endian host
}

void sys_headers_snapshot(machine_t& m)
{
	const auto map  = m.sysarg<uint64_t>(1);
	const auto nptr = m.sysarg<gaddr_t>(2);
	const auto nlen = m.sysarg<gaddr_t>(3);
	const auto out  = m.sysarg<gaddr_t>(4);
	const auto cap  = m.sysarg<gaddr_t>(5);
	std::string filter;
	if (map > 1 || !read_str(m, nptr, nlen, MAX_NAME, filter)) {
		m.set_result(FAILED);
		return;
	}
	Target target;
	http* hp = nullptr;
	const auto list = header_list(script_of(m), map == 1, target, hp);
	if (list.size() > MAX_HEADERS) {
		m.set_result(FAILED);
		return;
	}
	std::string packed;
	for (auto& [name, value] : list) {
		if (!filter.empty() && !iequals(name, filter))
			continue;
		if (name.size() > MAX_NAME || value.size() > MAX_VALUE) {
			m.set_result(FAILED);
			return;
		}
		put_u32(packed, name.size());
		put_u32(packed, value.size());
		packed.append(name);
		packed.append(value);
	}
	/* A short buffer is never partially written: the caller measured. */
	if (out != 0 && cap >= packed.size() && !packed.empty())
		m.copy_to_guest(out, packed.data(), packed.size());
	m.penalize(packed.size());
	m.set_result(packed.size());
}

/* Apply a committed header vector: every name whose values differ from the
   list the side holds now is replaced, and every name missing from the
   vector is removed. Entries the runtime did not mark dirty are present
   but untouched. All names are checked before any is applied. */
void headers_commit(machine_t& m, bool response)
{
	const auto addr = m.sysarg<gaddr_t>(1);
	auto& script = script_of(m);

	GuestVec vec;
	m.memory.memcpy_out(&vec, addr, sizeof(vec));
	if (vec.len > MAX_HEADERS) {
		m.set_result(FAILED);
		return;
	}
	std::vector<GuestHeader> raw(vec.len);
	if (vec.len > 0)
		m.memory.memcpy_out(raw.data(), vec.ptr, vec.len * sizeof(GuestHeader));

	struct Entry { std::string name; std::string value; bool dirty; };
	std::vector<Entry> entries;
	entries.reserve(raw.size());
	for (auto& h : raw) {
		Entry e;
		e.dirty = h.dirty != 0;
		if (!read_str(m, h.name.ptr, h.name.len, MAX_NAME, e.name)
			|| (e.dirty && !read_str(m, h.value.ptr, h.value.len, MAX_VALUE, e.value))) {
			m.set_result(FAILED);
			return;
		}
		entries.push_back(std::move(e));
	}

	Target target;
	http* hp = nullptr;
	/* Copies: applying edits to a Varnish header map moves its fields. */
	std::vector<std::pair<std::string, std::string>> before;
	for (auto& [n, v] : header_list(script, response, target, hp))
		before.emplace_back(n, v);
	if (target == Target::Refused
		|| (!response && vclv_phase(script.ctx()) != VCL_PHASE_RECV
			&& vclv_phase(script.ctx()) != VCL_PHASE_BACKEND_FETCH)) {
		refuse(m, response ? "a response header commit" : "a request header commit");
		return;
	}

	auto values_of = [&](std::string_view name) {
		std::vector<std::string_view> out;
		for (auto& [n, v] : before)
			if (iequals(n, name)) out.push_back(v);
		return out;
	};
	/* Work out the edits first, so a refused name changes nothing. */
	struct Edit { enum { Set, Add, Remove } op; std::string name; std::string value; };
	std::vector<Edit> edits;
	std::vector<std::string> present, written;
	auto contains = [](const std::vector<std::string>& set, std::string_view name) {
		for (auto& s : set) if (iequals(s, name)) return true;
		return false;
	};
	for (auto& e : entries) {
		if (!contains(present, e.name))
			present.push_back(e.name);
		if (!e.dirty)
			continue;
		if (!contains(written, e.name)) {
			written.push_back(e.name);
			const auto current = values_of(e.name);
			if (current.size() != 1 || current[0] != e.value)
				edits.push_back({Edit::Set, e.name, e.value});
		} else {
			edits.push_back({Edit::Add, e.name, e.value});
		}
	}
	for (auto& [n, v] : before)
		if (!contains(present, n) && !contains(written, n)) {
			written.push_back(n); // remove each name once
			edits.push_back({Edit::Remove, n, {}});
		}
	for (auto& edit : edits) {
		if (is_framing_header(edit.name)) {
			refuse(m, "a framing header write");
			return;
		}
		if (!valid_name(edit.name) || !valid_value(edit.value)) {
			m.set_result(FAILED);
			return;
		}
	}

	auto& synth = script.vcl_task().synth;
	for (auto& edit : edits) {
		int rc = 0;
		if (target == Target::Staged) {
			switch (edit.op) {
			case Edit::Set:    synth.set(edit.name, edit.value); break;
			case Edit::Add:    synth.add(edit.name, edit.value); break;
			case Edit::Remove: synth.unset(edit.name); break;
			}
			continue;
		}
		switch (edit.op) {
		case Edit::Set:
			rc = vclv_set(script.ctx(), hp, edit.name.data(), edit.name.size(),
				edit.value.data(), edit.value.size());
			break;
		case Edit::Add:
			rc = vclv_add(script.ctx(), hp, edit.name.data(), edit.name.size(),
				edit.value.data(), edit.value.size());
			break;
		case Edit::Remove:
			vclv_unset(hp, edit.name.data(), edit.name.size());
			break;
		}
		if (rc != 0) {
			m.set_result(FAILED);
			return;
		}
	}
	m.set_result(0);
}

/* ── Regular expressions ────────────────────────────────────────────── */

/* The compiled pattern for a guest pattern string. Every literal the
   policy uses was compiled at load; anything else is refused. */
const void* lookup_pattern(machine_t& m, gaddr_t ptr, gaddr_t len)
{
	std::string pattern;
	if (!read_str(m, ptr, len, MAX_PATTERN, pattern))
		return nullptr;
	const auto& program = script_of(m).program().vcl_program;
	const void* re = program ? program->pattern(pattern) : nullptr;
	if (re == nullptr) {
		/* The compiler lists every pattern it emits, so a miss is a
		   compiler/host disagreement worth a line, not a quiet refusal. */
		auto* ctx = ctx_of(m);
		if (ctx && ctx->vsl)
			VSLb(ctx->vsl, SLT_VCL_Error, "[%s] vcl: regex '%s' was not compiled at load",
				script_of(m).name().c_str(), pattern.c_str());
	}
	return re;
}

void sys_regex_match(machine_t& m)
{
	const auto [pptr, plen, sptr, slen, caps, maxcaps] =
		m.sysargs<gaddr_t, gaddr_t, gaddr_t, gaddr_t, gaddr_t, gaddr_t>();
	(void)caps;
	/* Generated VCL never asks for captures. */
	const void* re = maxcaps == 0 ? lookup_pattern(m, pptr, plen) : nullptr;
	std::string subject;
	if (re == nullptr || !read_str(m, sptr, slen, MAX_SUBJECT, subject)) {
		m.set_result(REGEX_REFUSED);
		return;
	}
	m.set_result(vclv_regex_match(re, subject.data(), subject.size()) ? 0 : FAILED);
}

struct Descriptor { uint64_t f[5]; };

void sys_regsub(machine_t& m)
{
	const auto pptr = m.sysarg<gaddr_t>(1);
	const auto plen = m.sysarg<gaddr_t>(2);
	const auto sptr = m.sysarg<gaddr_t>(3);
	const auto slen = m.sysarg<gaddr_t>(4);
	const auto dptr = m.sysarg<gaddr_t>(5);
	Descriptor d;
	m.memory.memcpy_out(&d, dptr, sizeof(d));
	const auto out = d.f[2], cap = d.f[3];
	const bool all = d.f[4] != 0;

	const void* re = lookup_pattern(m, pptr, plen);
	std::string subject, replacement;
	if (re == nullptr || !read_str(m, sptr, slen, MAX_SUBJECT, subject)
		|| !read_str(m, d.f[0], d.f[1], MAX_VALUE, replacement)) {
		m.set_result(FAILED);
		return;
	}
	/* Varnish's regsub, so `\1` in the replacement means what it means in
	   the VCL around the policy. It works on C strings, and neither side
	   can hold a NUL: header values and URLs cannot. */
	if (subject.find('\0') != std::string::npos || replacement.find('\0') != std::string::npos) {
		m.set_result(FAILED);
		return;
	}
	const char* result = vclv_regsub(ctx_of(m), all, subject.c_str(),
		const_cast<void*>(re), replacement.c_str());
	if (result == nullptr) {
		m.set_result(FAILED);
		return;
	}
	const size_t len = strlen(result);
	const size_t limit = out != 0 ? std::min<size_t>(MAX_VALUE, cap) : MAX_VALUE;
	if (len > limit) {
		m.set_result(FAILED);
		return;
	}
	if (out != 0 && len > 0)
		m.copy_to_guest(out, result, len);
	m.penalize(subject.size() + len);
	m.set_result(len);
}

void sys_regex_match_list(machine_t& m)
{
	const auto pptr = m.sysarg<gaddr_t>(1);
	const auto plen = m.sysarg<gaddr_t>(2);
	const auto rptr = m.sysarg<gaddr_t>(3);
	const auto rlen = m.sysarg<gaddr_t>(4);
	const auto dptr = m.sysarg<gaddr_t>(5);
	Descriptor d;
	m.memory.memcpy_out(&d, dptr, sizeof(d));
	const uint64_t flags = d.f[4];
	if ((flags & ~(REGEX_LIST_FIELD_VALUE | REGEX_LIST_ALL)) != 0 || rlen > MAX_LIST_BYTES) {
		m.set_result(FAILED);
		return;
	}
	const void* re = lookup_pattern(m, pptr, plen);
	if (re == nullptr) {
		m.set_result(REGEX_REFUSED);
		return;
	}
	std::string records;
	read_str(m, rptr, rlen, MAX_LIST_BYTES, records);

	/* The packed record format headers_snapshot emits. A list this host
	   would not have produced is refused, not parsed short. */
	std::string bits;
	uint64_t matched = 0, index = 0;
	for (size_t at = 0; at < records.size(); index++) {
		uint32_t nlen, vlen;
		if (index >= MAX_HEADERS || records.size() - at < 8) {
			m.set_result(FAILED);
			return;
		}
		memcpy(&nlen, &records[at], 4);
		memcpy(&vlen, &records[at + 4], 4);
		if (nlen > MAX_NAME || vlen > MAX_VALUE
			|| records.size() - at - 8 < uint64_t(nlen) + vlen) {
			m.set_result(FAILED);
			return;
		}
		const char* name = &records[at + 8];
		const bool value_field = flags & REGEX_LIST_FIELD_VALUE;
		const char* subject = value_field ? name + nlen : name;
		const size_t sublen = value_field ? vlen : nlen;
		if (bits.size() <= index / 8)
			bits.push_back('\0');
		if (vclv_regex_match(re, subject, sublen)) {
			bits[index / 8] |= char(1u << (index % 8));
			matched++;
		}
		at += 8 + size_t(nlen) + vlen;
	}
	if (d.f[2] != 0) {
		if (d.f[3] < bits.size()) {
			m.set_result(FAILED);
			return;
		}
		if (!bits.empty())
			m.copy_to_guest(d.f[2], bits.data(), bits.size());
	}
	m.set_result(matched);
}

/* ── Hashing and signing (the digest vmod) ──────────────────────────── */

const EVP_MD* algorithm(uint64_t alg, bool keyed)
{
	switch (alg) {
	case 1:  return keyed ? nullptr : EVP_sha256();
	case 2:  return keyed ? nullptr : EVP_sha512();
	case 16: return keyed ? EVP_sha256() : nullptr;
	case 17: return keyed ? EVP_sha512() : nullptr;
	}
	return nullptr;
}

void sys_hash(machine_t& m)
{
	const auto alg = m.sysarg<uint64_t>(1);
	const auto ptr = m.sysarg<gaddr_t>(2);
	const auto len = m.sysarg<gaddr_t>(3);
	const auto out = m.sysarg<gaddr_t>(4);
	const EVP_MD* md = algorithm(alg, false);
	std::string data;
	if (md == nullptr || out == 0 || !read_str(m, ptr, len, MAX_CRYPTO_INPUT, data)) {
		m.set_result(FAILED);
		return;
	}
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	if (!EVP_Digest(data.data(), data.size(), digest, &dlen, md, nullptr)) {
		m.set_result(FAILED);
		return;
	}
	m.copy_to_guest(out, digest, dlen);
	m.set_result(dlen);
}

bool hmac(machine_t& m, const EVP_MD*& md, unsigned char* mac, unsigned int& maclen)
{
	const auto alg  = m.sysarg<uint64_t>(1);
	const auto kptr = m.sysarg<gaddr_t>(2);
	const auto klen = m.sysarg<gaddr_t>(3);
	const auto mptr = m.sysarg<gaddr_t>(4);
	const auto mlen = m.sysarg<gaddr_t>(5);
	md = algorithm(alg, true);
	std::string key, msg;
	if (md == nullptr || !read_str(m, kptr, klen, MAX_CRYPTO_INPUT, key)
		|| !read_str(m, mptr, mlen, MAX_CRYPTO_INPUT, msg))
		return false;
	return HMAC(md, key.data(), int(key.size()),
		reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
		mac, &maclen) != nullptr;
}

void sys_sign(machine_t& m)
{
	const auto out = m.sysarg<gaddr_t>(6);
	const EVP_MD* md;
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen = 0;
	if (out == 0 || !hmac(m, md, mac, maclen)) {
		m.set_result(FAILED);
		return;
	}
	m.copy_to_guest(out, mac, maclen);
	m.set_result(maclen);
}

void sys_verify(machine_t& m)
{
	const auto tag_ptr = m.sysarg<gaddr_t>(6);
	const EVP_MD* md;
	unsigned char mac[EVP_MAX_MD_SIZE], tag[EVP_MAX_MD_SIZE];
	unsigned int maclen = 0;
	if (!hmac(m, md, mac, maclen)) {
		m.set_result(FAILED);
		return;
	}
	m.memory.memcpy_out(tag, tag_ptr, maclen);
	m.set_result(CRYPTO_memcmp(mac, tag, maclen) == 0 ? 1 : 0);
}

/* ── The typed slot ─────────────────────────────────────────────────── */

void sys_typed(machine_t& m)
{
	switch (m.sysarg<int64_t>(0)) {
	case TYPED_REQ_HEADERS_COMMIT:  return headers_commit(m, false);
	case TYPED_RESP_HEADERS_COMMIT: return headers_commit(m, true);
	case TYPED_HASH:                return sys_hash(m);
	case TYPED_SIGN:                return sys_sign(m);
	case TYPED_VERIFY:              return sys_verify(m);
	case TYPED_SET_GRACE:           return set_duration(m, VCL_GRACE, m.sysarg<uint64_t>(1));
	case TYPED_SET_KEEP:            return set_duration(m, VCL_KEEP, m.sysarg<uint64_t>(1));
	case TYPED_REQ_REMOVE_HEADER:   return remove_header(m, false);
	case TYPED_RESP_REMOVE_HEADER:  return remove_header(m, true);
	case TYPED_SET_OUTCOME_PLAIN:   return sys_set_outcome_plain(m);
	case TYPED_REGSUB:              return sys_regsub(m);
	case TYPED_HEADERS_SNAPSHOT:    return sys_headers_snapshot(m);
	case TYPED_REGEX_MATCH_LIST:    return sys_regex_match_list(m);
	case TYPED_CLIENT_IP:           return sys_client_ip(m);
	case TYPED_CACHE_DURATION:      return sys_cache_duration(m);
	case TYPED_INCLUDE_READ:        return include_read(m);
	case TYPED_CACHE_STATUS:        return sys_cache_status(m);
	default:
		m.set_result(FAILED);
		return;
	}
}

} // anonymous namespace

/* The handler table is per machine *type*, so these are reachable from
   every tenant program, VCL or not. That is harmless: each handler works
   on the calling Script and its ctx, like the VMOD API does, and the
   compiler guest's include read is gated by a per-thread session. */
void install_syscalls()
{
	machine_t::install_syscall_handlers({
		{SYS_REQ_GET_METHOD,  sys_req_get_method},
		{SYS_REQ_GET_URL,     sys_req_get_url},
		{SYS_REQ_GET_HEADER,  sys_req_get_header},
		{SYS_REQ_SET_HEADER,  sys_req_set_header},
		{SYS_REQ_SET_URL,     sys_req_set_url},
		{SYS_RESP_GET_HEADER, sys_resp_get_header},
		{SYS_RESP_SET_HEADER, sys_resp_set_header},
		{SYS_RESP_GET_STATUS, sys_resp_get_status},
		{SYS_LOG,             sys_log},
		{SYS_RETURN_ACTION,   sys_return_action},
		{SYS_SET_TTL,         sys_set_ttl},
		{SYS_REGEX_MATCH,     sys_regex_match},
		{SYS_TYPED,           sys_typed},
	});
}

} // rvs::vcl
