#pragma once

void riscv_SetCacheable(VRT_CTX, bool a);
bool riscv_GetCacheable(VRT_CTX);
void riscv_SetTTL(VRT_CTX, float ttl);
float riscv_GetTTL(VRT_CTX);
long riscv_SetBackend(VRT_CTX, VCL_BACKEND);

#define HDR_FIRST     HTTP_HDR_FIRST
#define HDR_INVALID   UINT32_MAX
