#pragma once

/* vdef.h unconditionally defines dummy LIKELY/UNLIKELY, which clashes
   with libriscv's definitions. Keep the branch hints. */
#undef LIKELY
#undef UNLIKELY
extern "C" {
# include <cache/cache.h>
# include <vre.h>
# include <vsb.h>
# include <vcl.h>
# include <vapi/vsl_int.h>
# include <vsha256.h>
	void *riscv_ws_alloc_spare(struct ws *ws, unsigned bytes, unsigned keep);
}
#ifdef VARNISH_PLUS
# define RISCV_NO_VXID 0
#else
# define RISCV_NO_VXID NO_VXID
#endif
#undef LIKELY
#undef UNLIKELY
#define LIKELY(x)   __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)
