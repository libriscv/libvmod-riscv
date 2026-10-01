#pragma once
#include "vcl_stats.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

struct vrt_ctx;
namespace rvs {
class Script;
struct MachineInstance;
struct SandboxTenant;
}

namespace rvs::vcl {

/**
 * What the host knows about a tenant program that was compiled from VCL,
 * built once when the program loads and shared by every fork of it.
 *
 * A compiled policy is not an ordinary tenant program: its main() just
 * exits, it exports its hooks by name (on_recv,
 * on_backend_request, on_backend_response, on_deliver) instead of
 * registering callbacks, and it talks to Varnish through the policy ABI at
 * 540..=560 (abi.hpp) rather than the VMOD API at 500..=539.
 */
struct Program
{
	/* Every regex literal the policy uses, from `.carapace.regex`, compiled
	   with Varnish's engine when the program loads. The generated code only
	   ever passes one of these, so a lookup miss is a refusal. */
	std::unordered_map<std::string, void*> patterns;

	/* The request-global region (`.carapace.globals`): where it lives, and
	   the image each request starts from. Written once into the master VM
	   after main(), so every fork starts from it. */
	uint64_t globals_address = 0;
	std::vector<uint8_t> globals_image;

	/* The declared statistics (`.carapace.stats`), bound to their tenant
	   counters. */
	std::vector<Stat> stats;

	const void* pattern(std::string_view) const;

	/* Validate the policy sections, compile its patterns, seed its globals
	   into the master VM, and register its hooks as the tenant callbacks.
	   Throws with a message naming what is wrong. */
	static std::unique_ptr<Program> install(Script& master, MachineInstance&);

	Program() = default;
	Program(const Program&) = delete;
	Program& operator=(const Program&) = delete;
	~Program();
};

/**
 * The synthetic response a policy is building before Varnish has one.
 *
 * Varnish runs vcl_synth as its own subroutine, after vcl_recv or
 * vcl_deliver returns. The compiler folds the policy's `sub vcl_synth` into
 * the hook that returns `synth(...)` instead, so its `resp.http` writes and
 * `synthetic()` happen while ctx->http_resp is absent (vcl_recv) or is the
 * response being abandoned (vcl_deliver). They are staged here, starting
 * from an empty response, and applied when `riscv.run()` is called from
 * vcl_synth.
 */
struct StagedSynth
{
	bool active = false;
	uint16_t status = 0;
	std::string reason;
	std::string body;
	std::vector<std::pair<std::string, std::string>> headers;
	/* Names the policy removed, so a Varnish default of the same name
	   (Content-Type, Retry-After) is removed too when the stage applies. */
	std::vector<std::string> removed;

	const std::string* get(std::string_view name) const;
	void set(std::string_view name, std::string_view value);
	void add(std::string_view name, std::string_view value);
	void unset(std::string_view name);
};

/**
 * Per-task state of a compiled policy, living in the task's Script. The
 * client fork keeps it from vcl_recv through vcl_deliver; a backend fork has
 * its own.
 */
struct TaskState
{
	StagedSynth synth;
	/* Each statistic word as the host last read it (fold_stats). */
	std::vector<uint64_t> stat_seen;
};

/* Apply a staged synthetic response in vcl_synth. */
void apply_synth(Script&);

/* Compile a `.vcl` file in the sandbox and load the result as a tenant
   program. Compiler warnings go to the log. Throws on a failed compile. */
std::shared_ptr<MachineInstance> load(const std::string& path,
	const struct vrt_ctx*, struct SandboxTenant*);

/* Whether a tenant filename names VCL source rather than a program. */
bool is_vcl_source(std::string_view filename);

} // rvs::vcl
