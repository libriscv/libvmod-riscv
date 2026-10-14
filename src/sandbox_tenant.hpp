#pragma once
#include "script.hpp"
#include "tenant.hpp"
#include "machine_instance.hpp"
#include <mutex>
#define SCRIPT_MAGIC 0x83e59fa5

namespace rvs {

struct SandboxTenant
{
	using ghandler_t = std::function<void(Script&)>;

	Script* vmfork(const vrt_ctx*, bool debug);
	void load(const vrt_ctx*);
	bool no_program_loaded() const noexcept { return this->program == nullptr; }
	/* The file load() reads the program from, with $vars applied. */
	std::string program_path() const;
	/* Whether a reload may keep this tenant's program when its
	   configuration and program file are unchanged. A Rust project is
	   rebuilt every time, as its sources are not the one file stamped. */
	bool reusable_source() const;

	SandboxTenant(const vrt_ctx*, const TenantConfig&);
	static void init();
	void init_vmods(const vrt_ctx*);

	/* Initialized during vcl_init. Once finalize_tenants() has published
	   a tenant it may be shared by several VCLs, and its configuration is
	   no longer changed, except argv inside a live update. */
	const uint64_t magic = 0xb385716f486938e6;
	TenantConfig config;
	/* Serializes live updates of this tenant against each other and
	   against a VCL reload looking for a tenant to reuse. Guards
	   file_stamp, and argv while a live update temporarily extends it. */
	std::mutex update_mtx;
	/* The program file as it was when the program was loaded from it,
	   or when a live update last wrote it. */
	FileStamp file_stamp;
	/* Hot-swappable program */
	std::shared_ptr<MachineInstance> program = nullptr;
	/* Program for debugging */
	std::shared_ptr<MachineInstance> debug_program = nullptr;
};

} // rvs
