#ifndef _LAYOUT_MAPPING
#include "../../includes/layout_mapping.h"
#endif


void *(*orig_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);


// Move to syscall.c, make a wrapper for it to write -1 for -14 and 0 for -2
// Errors -2(think it is OK), -36 -14(AT_EACCESS)
int __access_check_x86_64(const char *addr, int mode) {
	long ret;
	// int err;
	__asm__ volatile(
					"xor %%rdx, %%rdx\n"
					"mov %0, %%rdi\n"
					"mov %1, %%rsi\n"
					"mov $21, %%rax\n"			// rax SYSCALL number 	RDI 1 arg, RSI 2 arg, rdx, 3 arg
					"syscall" : : "g"(addr), "g"(mode));
	asm ("mov %%rax, %0" : "=r"(ret));

	if (ret == -14)	// AT_EACCESS -14
		return -1;
	if (ret == -2)	// If ok, -2
		return 0;
	return ret;
}


long __mprotect_x86_64(unsigned long start, size_t len, unsigned long prot) {
	long ret;
	__asm__ volatile(
					"mov %0, %%rdi\n"
					"mov %1, %%rsi\n"
					"mov %2, %%rdx\n"
					"mov $10, %%rax\n"
					"syscall" : : "g"(start), "g"(len), "g"(prot));
	asm ("mov %%rax, %0" : "=r"(ret));

	return ret;
}

// Map sections in segments, from shortest offset to longest, have the st_size
// fstruct with malloc
// find the beggining of the program, go far back and over the helper_addr to be sure there is not anything missing, don't need 0x7ffff7
// Make it reusable for VDSO injection maybe VDSO
// align the segments sections with the mappings
uintptr_t check_first_allocated_page(uintptr_t prepared_addr, size_t nmemb, size_t size) {
	// find which pages are allocated, access helper_addr-0x2000 (64bit); if NOACCESS, too many times before, probably have the first one

	// 20, just testin
	// HAS TO BE & ~0x1fff
	// int step_size = 0x2000;		// 64bit
	int is_allocated;
	uintptr_t addr_to_check = prepared_addr;

	int i = 0;
	while (i < nmemb) {
		// puts("\t\t\tAAAAAAAAAAAAAAAAAAA");
		addr_to_check = prepared_addr+(i*size);
		is_allocated = __access_check_x86_64((const char *)addr_to_check, F_OK);

		if (is_allocated != 0 && is_allocated != -1)
			DEBUG("Some fucking error occured @check_pages [[ %i ]]\n", is_allocated);

		// if (is_allocated == -1)
		// 	printf("[-] 0x%p\t|\t EMPTY", addr_to_check);
		if (is_allocated == 0)
			return addr_to_check;
			// printf("\n[+] 0x%p\t|\t ++ok+++", addr_to_check);

		i++;
	}

	return 0;

// 	uintptr_t base = (uintptr_t)orig_main & ~0x0000000000001fff;	// NOPE, orig_main doesn't have to be in the first page, it can be anywhere
// 	printf("\n[[  0x%p  ]]\n", (base + (uintptr_t)got_addr));
// 	hexdump((uintptr_t)(base + (uintptr_t)got_addr), 0x200);
}

uintptr_t and_not_val(long unsigned num) {
	int i = 0;
    for (; num > 0; i += 4)
        num = num >> 4;
    
    #ifdef ARCH64
		return (0xffffffffffffffff >> (64-i));		// make it uintptr_t or whatever 16byte on 64bit
	#endif

	#ifdef ARCH32
		return (0xffffffff >> 32-i);
	#endif
}
// find base by checking \x7f ELF at page

int _strncmp(char *str_a, char *str_b, size_t len) {
	len++;
	for (int i = 0; i < len; i++) {
		if (str_a[i] == '\x00' && str_b[i] != '\x00')
			return -1;
		if (str_a[i] != '\x00' && str_b[i] == '\x00')
			return -1;
		
		if ((char)str_a[i] != (char)str_b[i])
			return -1;
	}
	return 0;
}

void* _memset(void *p, int val, size_t len){
	register size_t i;
	for(i=0;i<len;++i)
		((char *)p)[i]=val;
	return p;
}

uintptr_t find_base(uintptr_t helper_addr, struct elf_struct *self_elf, uintptr_t got_addr) {
	// if there is anyhting allocted before the first section in the program, it will take it as the first section
	Elf_Shdr current;
	uintptr_t addr_to_check, base_addr, try_base;
	// uintptr_t base_addr;
	int first_sec_i = 0;

	for (int i = 0; i < self_elf->ehdr->e_shnum; i++) {
		current = self_elf->sec.shdr[i];

		if (i == first_sec_i) {
			if (self_elf->sec.shdr[i].sh_size == 0) {
				first_sec_i++;
				continue;
			}

			try_base 		= helper_addr & ~(and_not_val(current.sh_offset));
			addr_to_check	= try_base+current.sh_offset;

			base_addr = check_first_allocated_page(addr_to_check-CHECK_MEM_START_MINUS, CHECK_MEM_NMEMB, CHECK_MEM_BY_SIZE);
			if (base_addr == 0) {
				// Were fucked, should not happen unlikely()
				return 0xdeadc0de;
			}
			base_addr = base_addr - current.sh_offset;
			DEBUG("[+] The program base address is 0x%lx\n", base_addr);
			goto next;
		}

		addr_to_check = base_addr + current.sh_offset;
		int ret = __access_check_x86_64((const char *)addr_to_check, F_OK);
		if (ret == 0) {
			DEBUG("++ok+++ 0x%lx\n", addr_to_check);
			goto next;
		}
		printf("FAILED @ 0x%lx\n", addr_to_check);

	next:
		// previous = current;
		continue;
	}
	// If there is .got.plt, it will choose .got.plt
	// I want .got, .got.plt points to .plt, .got points to libc
	// Map offsets with Rel
	// find libc base, check each entry with ELF_R_SYM offset /-for name
	// replace if I will

	// If the got_addr  (PIE, GOT - eg. 0x3fd8, where Base = eg. 0x0000555555554000 )
	// 					(NoPIE, GOT - eg. 0x401036, where Base = 0x400000)
	if (( got_addr > base_addr )){
		hexdump((uintptr_t)(got_addr), 0x200);
	} else {
		hexdump((uintptr_t)(base_addr+got_addr), 0x200);
	}

	
	if (self_elf->dyn.symbols->name != NULL) {			// *** MPROTECT SYSCALL

		for (int i = 0; self_elf->dyn.symbols[i].name != NULL; i++) {
			if (strncmp(self_elf->dyn.symbols[i].name,"mmap", 4) == 0) {

				unsigned long* addr = (unsigned long*)(base_addr+self_elf->dyn.symbols[i].offset);
				// unsigned long *addr = (unsigned long*)0x5555555fe000;	// 0x5555555f69d0
				// unsigned long *addr = (unsigned long*)0x5555555f6000;

				// int is_ok = __access_check_x86_64((const char *)addr, F_OK);

				__mprotect_x86_64((uintptr_t)addr&~0x1fff, (size_t)0x2000, PROT_WRITE | PROT_EXEC | PROT_READ);
				// int ret = mprotect((void*)(uintptr_t)addr, 0x8, PROT_WRITE);
				// memset((unsigned char*)addr+4, (uintptr_t)0xdd, 1);
				DEBUG("[+] %p OUR EVIL FUNCTION %p\n", addr, wassup);
				DEBUG("===================================================\n");
				// uintptr_t addr = base_addr+self_elf->dyn.symbols[i].offset;
					hexdump((uintptr_t)addr, sizeof(uintptr_t));
					orig_mmap = (void*)*addr;
					DEBUG("BYTES: ");
					for (int n = 8; n > 0; n--) {
						unsigned char c = ((uintptr_t)wassup >> (64-n*8));// & ~(0xffffffffffffffff >> 64+8-n*8);
						DEBUG("%x-", c);
						memset((unsigned char*)addr+8-n, c, 1);	
					}
					puts("\n\n\n\nAFTER! - ");
					
					DEBUG("END==== %i %lx\n", ret, (uintptr_t)mmap);
					hexdump((uintptr_t)addr, sizeof(uintptr_t));
			}
		}
		DEBUG(">>>>>%lx<<<<<\n", (uintptr_t)exit);
	}
	// free((void*)self_elf->dyn.symbols);

	return 0xdeadbeef;
}


void *wassup(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	printf("*********MMAP - addr %p, length %li, fd %i, offset %lu\n", addr, length, fd, offset);
	return orig_mmap(addr, length, prot, flags, fd, offset);
}


//
// ~=~=~ @hexdump : Simple Hexdump function
// ~addr: the address to start from (uintptr_t)
// ~size: distance in bytes			(uint64_t) 
void hexdump(uintptr_t addr, uint64_t size) {
	uintptr_t curr_addr = addr;
	fprintf(stdout, "========HEXDUMP BEGIN========");
	for (int i = 0; i < size; curr_addr++, i++) {
		if (i % 16 == 0) {
			fprintf(stdout, "\n");
			printf("0x%lx\t|\t", curr_addr);
		}
		// puts("HIHIHI\n");
		// printf("%lx", (addr+i));
		fprintf(stdout, "%x ", ((unsigned char*)addr)[i]);
	}
	fprintf(stdout, "\n========HEXDUMP END========\n");
}