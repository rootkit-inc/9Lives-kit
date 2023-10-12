#ifndef _LAYOUT_MAPPING
#define _LAYOUT_MAPPING
#endif

#ifndef _ELF_HELPER
#include "../includes/elf.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define CHECK_MEM_START_MINUS 	320*0x2000
#define CHECK_MEM_NMEMB 		10000
#define CHECK_MEM_BY_SIZE 		0x1000

// Need segments, dynamic, text. data

int __access_check_x86_64(const char *, int);
uintptr_t check_first_allocated_page(uintptr_t, size_t, size_t);
uintptr_t find_base(uintptr_t, struct elf_struct *, uintptr_t got_addr);
// void sort_shdr(struct elf_struct *);
void hexdump(uintptr_t, uint64_t);
long __mprotect_x86_64(unsigned long, size_t, unsigned long);