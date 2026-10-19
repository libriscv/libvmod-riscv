#pragma once
/* The slice of varnishd the scripting API calls into, rebuilt so the
   system call handlers can run outside of Varnish. See fake_varnish.cpp. */
#include <cstddef>
#include <cstdint>

struct ws;
struct vrt_ctx;
struct http;

namespace fake {

/* One workspace per task. Every allocation is its own heap block, so
   ASan sees the exact bounds of each one, and the total is capped at
   `size` like a real workspace. */
struct ws* ws_new(size_t size);
void ws_delete(struct ws*);

/* Stand-ins for struct req and struct busyobj: the API only stores
   into them through riscv_Set*(), or checks them for NULL. */
struct req {
	const void* director_hint = nullptr;
	unsigned char digest[32] {};
};
struct busyobj {
	const void* director_req = nullptr;
	bool  uncacheable = false;
	float ttl = 120.0f;
};

/* Copy of the request header set, for VRT_Rollback(). */
void snapshot_http(const struct vrt_ctx*);
void forget_snapshots();

/* Number of VRT_fail() calls since the last reset. */
extern unsigned vrt_failures;

/* Reads every byte a header field points at, so ASan checks it. */
uint32_t touch_http(const struct http*);

} // fake
