/*
 * The sandboxed VCL compiler (vcl/vclc.elf), embedded in the VMOD so that
 * building or running it needs no Rust or RISC-V toolchain. Both build
 * systems define VCLC_ELF_PATH as the blob's absolute path, which LTO needs
 * since it assembles this at link time, and add a dependency on the blob.
 */
__asm__(
	"	.section .rodata\n"
	"	.global vclc_elf\n"
	"	.hidden vclc_elf\n"
	"	.balign 16\n"
	"vclc_elf:\n"
	"	.incbin \"" VCLC_ELF_PATH "\"\n"
	"	.global vclc_elf_end\n"
	"	.hidden vclc_elf_end\n"
	"vclc_elf_end:\n"
	"	.previous\n"
);
