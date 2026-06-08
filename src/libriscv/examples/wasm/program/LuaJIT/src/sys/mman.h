#include <stddef.h>

#define PROT_READ		0x1
#define PROT_WRITE		0x2
#define PROT_EXEC		0x4
#define MAP_PRIVATE		    0x02
#define MAP_ANONYMOUS		0x20
#define MAP_FAILED		((void *)-1)

static inline void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset)
{
	register void *addr_asm __asm__("a0") = addr;
	register size_t length_asm __asm__("a1") = length;
	register int prot_asm __asm__("a2") = prot;
	register int flags_asm __asm__("a3") = flags;
	register int fd_asm __asm__("a4") = fd;
	register long offset_asm __asm__("a5") = offset;
	register long syscall_id __asm__("a7") = 222; // RISC-V syscall number for mmap

	__asm__ volatile("ecall" : "+r"(addr_asm) : "r"(length_asm), "r"(prot_asm), "r"(flags_asm), "r"(fd_asm), "r"(offset_asm), "r"(syscall_id));
	return addr_asm; // Assume success for this example
}
static inline int mprotect(void *p, size_t sz, int prot)
{
    register void *p_asm __asm__("a0") = p;
	register size_t sz_asm __asm__("a1") = sz;
	register int prot_asm __asm__("a2") = prot;
	#define SYS_mprotect 226 // RISC-V syscall number for mprotect
	register long syscall_id __asm__("a7") = SYS_mprotect;

	__asm__ volatile("ecall" : "+r"(p_asm) : "r"(sz_asm), "r"(prot_asm), "r"(syscall_id));
	return 0; // Assume success for this example
}
static inline int munmap(void *addr, size_t length)
{
	register void *addr_asm __asm__("a0") = addr;
	register size_t length_asm __asm__("a1") = length;
	register long syscall_id __asm__("a7") = 215; // RISC-V syscall number for munmap

	__asm__ volatile("ecall" : "+r"(addr_asm) : "r"(length_asm), "r"(syscall_id));
	return 0; // Assume success for this example
}
