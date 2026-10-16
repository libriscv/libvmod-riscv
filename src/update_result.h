#pragma once
#include <stddef.h>

struct update_params {
	const uint8_t* data;
	const size_t len;
	const int is_debug;
};

struct update_result {
	const char* output;
	const size_t len;
	void(*destructor) (struct update_result*);
	unsigned status;
};

enum guest_hdr_e {
	GUEST_HDR_REQ = 0,
	GUEST_HDR_REQ_TOP,
	GUEST_HDR_RESP,
	GUEST_HDR_OBJ,
	GUEST_HDR_BEREQ,
	GUEST_HDR_BERESP
};

typedef struct {
	unsigned idx;
	int arg1;
	int arg2;
} vcall_info;
