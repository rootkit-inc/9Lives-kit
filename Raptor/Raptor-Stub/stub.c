#include "elf.h"

#define SYS_READ  0
#define SYS_WRITE 1
#define SYS_MMAP  9
#define SYS_OPEN  2
#define SYS_CLOSE 3
#define SYS_MPROTECT 10
#define SYS_EXIT 0x3c
#define SYS_MUNMAP 0xb
#define SYS_LSEEK 0x8
#define SYS_FSTAT 0x5

#define O_WRONLY	00000001
#define O_CREAT		00000100


#define PROT_READ	0x1
#define PROT_WRITE	0x2
#define PROT_EXEC	0x4
#define MAP_PRIVATE 0x02
#define MAP_FIXED	0x10
#define MAP_ANONYMOUS	0x20
#define MAP_ANON MAP_ANONYMOUS

#define PAGE_ALIGN_DOWN(addr) (addr & ~0xfff)
#define PAGE_ALIGN(addr) ((addr + 0xfff) & ~0xfff)


/**
/ * *~*~* THE LAYER0 & METADATA *~*~*
*/
static data_tmp_t data_section;
static char layer0[PROTECTED_BINARY_SIZE];


static struct stat {
	unsigned long	st_dev;
	unsigned long	st_ino;
	unsigned long	st_nlink;

	unsigned int		st_mode;
	unsigned int		st_uid;
	unsigned int		st_gid;
	unsigned int		__pad0;
	unsigned long	st_rdev;
	long		st_size;
	long		st_blksize;
	long		st_blocks;	/* Number 512-byte blocks allocated. */

	unsigned long	st_atime;
	unsigned long	st_atime_nsec;
	unsigned long	st_mtime;
	unsigned long	st_mtime_nsec;
	unsigned long	st_ctime;
	unsigned long	st_ctime_nsec;
	long		__unused[3];
};

#define DEBUG_PRINT_SYMBOLS


static long __syscall_1_x86_64(int SYSNUM, long arg1)
{
	long ret;

	asm("syscall" : "=a"(ret) : "a"(SYSNUM),"D"(arg1));

	return ret;
}


static long __syscall_3_x86_64(int SYSNUM, long arg1, long arg2, long arg3)
{
	long ret;

	asm("syscall" : "=a"(ret) : "a"(SYSNUM),"D"(arg1),"S"(arg2),"d"(arg3));

	return ret;
}

static long __syscall_6_x86_64(int SYSNUM, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6)
{
	long ret;

	register long ra10 asm("r10") =  arg4;
	register long ra8 asm("r8") =  arg5;
	register long ra9 asm("r9") =  arg6;

	asm("syscall" : "=a"(ret) : "a"(SYSNUM),"D"(arg1),"S"(arg2),"d"(arg3),"r"(ra10),"r"(ra8),"r"(ra9));

	return ret;
}


typedef int (*__libc_start_main_t)(	int (*main) (int, char * *, char * *),
						int argc,
						char * * ubp_av,
						void (*init) (void),
						void (*fini) (void),
						void (*rtld_fini) (void),
						void (* stack_end));


static void _puts(char *str, size_t len) {
	__syscall_3_x86_64(SYS_WRITE, 1, (long int)str, len);
}

static char *_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset) {
	return (char *)__syscall_6_x86_64(SYS_MMAP, (long)addr, length, prot, flags, fd, offset);
}

static int myclose(int fd) {
	return __syscall_1_x86_64(SYS_CLOSE, fd);
}

void *_memcpy(void *dest, void *src, size_t size) {
	for (int i = 0; i < size; ++i) {
		((unsigned char *)dest)[i] = ((unsigned char*)src)[i];
	}

	return dest;
}

static int _strncmp_no_strict(char *str_a, char *str_b, size_t len) {
	for (int i = 0; i < len; i++) {
		if ((char)str_a[i] != (char)str_b[i])
			return -1;
	}
	return 0;
}
static int _strncmp(char *str_a, char *str_b, size_t len) {
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

static size_t _len(char *str) {
	size_t l;

	for (l = 0; str[l] != '\x00'; l++) {}

	return l;
}


// -Wdangling-pointer=0
#define _VA_SIZE(...) ( (int)sizeof((char*[]){__VA_ARGS__}) )

#define DEBUG(...) ({												\
	char **args = ((char*[_VA_SIZE(__VA_ARGS__)]) {__VA_ARGS__});	\
	for (int i = 0; i < sizeof(args); i++) {						\
		if (args[i] == 0)											\
			continue;												\
		_puts(args[i], _len(args[i]));							\
	}														\
})

#define DIE(...) ({													\
		DEBUG(__VA_ARGS__);											\
		asm("syscall" : : "a"(SYS_EXIT), "D"(-1));					\
})


static int hex_len(unsigned long hex) {
    for (int i = 0; i < 16; i++) {
        if ((hex >> 4*i) == 0)
            return i;
    }
    return 16;
}

#define P_HEX64(hex) ({																		\
		    char x[18] = {'0','x',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};							\
		    int len = hex_len(hex);															\
		    for (int i = 1; i <= len; i++) {												\
		        char tmp = (char)((hex >> (4*len-(4*i))) &  ~(0xffffffffffffffff << 4 ));	\
		        if (tmp >= 0xa && tmp < 0x10)												\
		            x[i-1+2] = tmp+0x60-9;													\
		        else if (tmp < 0xa)															\
		            x[i-1+2] = tmp+0x30;														\
		    }																			\
		    (char*)x;																\
})



static void get_dynsym(elf_t *elf) {
	for (int i = 0; i < elf->ehdr->e_shnum; i++) {
		switch(elf->shdr[i].sh_type) {
		case SHT_DYNSYM:
			elf->dynsym.sym = (Elf64_Sym *) (elf->memmap + elf->shdr[i].sh_offset);
			elf->dynsym.str = (char *) (elf->memmap + elf->shdr[elf->shdr[i].sh_link].sh_offset);
			elf->dynsym.sec = &elf->shdr[i];

			for (int j = 0; j < (elf->shdr[i].sh_size/sizeof(Elf64_Sym)); j++) {
				// if (ELF64_ST_TYPE(elf->dynsym.sym[j].st_info) == STT_GNU_IFUNC)
				// _puts(elf->dynsym.str + elf->dynsym.sym[j].st_name, 10);
			}
			continue;
		case SHT_SYMTAB:
			elf->symtab.sym = (Elf64_Sym*) (elf->memmap + elf->shdr[i].sh_offset);
			elf->symtab.str = (char *) (elf->memmap + elf->shdr[elf->shdr[i].sh_link].sh_offset);
			elf->symtab.sec = &elf->shdr[i];

			for (int j = 0; j < (elf->shdr[i].sh_size/sizeof(Elf64_Sym)); j++) {
				// #ifdef DEBUG_PRINT_SYMBOLS
						DEBUG("New symbol in SYMTAB - ", elf->strtab + elf->shdr[i].sh_name,
							" - ", elf->symtab.str + elf->symtab.sym[j].st_name, "\n");
				// #endif
			}
			continue;
		}
	}
}


// __libc_start_main_t
static uintptr_t find_sym_addr(elf_t *elf, char *name) {
	DEBUG("[~] Looking for sym - \"", name, "\" - ");
	for (int i = 0; i < (elf->dynsym.sec->sh_size/sizeof(Elf64_Sym)); i++) {
		if (elf->dynsym.str[elf->dynsym.sym[i].st_name] == '\x00')
			continue;

		if (_strncmp(elf->dynsym.str + elf->dynsym.sym[i].st_name, name, _len(name)) == 0) {
			DEBUG("FOUND @", P_HEX64(elf->dynsym.sym[i].st_value), "\n");
			return  elf->dynsym.sym[i].st_value;
		}
	}
	DEBUG("NOT FOUND    -1\n");
	return -1;
}

static int _open(char *path, int flagz) {
	return __syscall_3_x86_64(SYS_OPEN, (long int)path, 0, flagz);
}

#define X86_64_LIBC_POSIB_COUNT 5

static char *libc_path_x86_64[X86_64_LIBC_POSIB_COUNT] = {
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib64/libc.so.6",
		"/usr/local/lib64/libc.so.6"
	};

static uintptr_t str_to_hex(char *str, int len) {
	uintptr_t ret = 0;
	if (len > 16) return -1;

	for (int i = 0; i < len; i++) {
		if (str[i] >= 0x61 && str[i] <= 0x66)
			ret = (ret << 4) | (str[i]-87);
		if (str[i] >= 0x30 && str[i] <= 0x39)
			ret = (ret << 4) | (str[i]-48);
	}

	return ret;
}

typedef struct {
	uintptr_t libc_base;
	char *libc;
} ret_me;

#define RET_ME_ERR(...) ({							\
	ret_me r;											\
	r.libc_base = -1;									\
	r.libc = "\x00";									\
	r; 													\
})

static ret_me find_libc_base(char *buf) {
	int j;
	for (int i = 0; i < 0x1000; i++) {
		if (buf[i] == '\x00')
			return RET_ME_ERR(-1);

		for (int l = 0; l < X86_64_LIBC_POSIB_COUNT; l++) {
			// int str_len = _len(libc_path_x86_64[l]);
				if (_strncmp_no_strict(libc_path_x86_64[l], &buf[i], _len(libc_path_x86_64[l])) == 0) {
					while ((char)buf[i] != '\x00' && (char)buf[i] != '\n') i--;

					for (j = 0; j < 20 + 1; j++) {
						if ((buf[i+j]) == '-') {
							break;
						}
					}
					uintptr_t base = str_to_hex(&buf[i], j);
					ret_me ret;
					ret.libc_base = base;
					ret.libc = libc_path_x86_64[l];
					DEBUG("[+] Found libc - ", ret.libc, " @ ", P_HEX64(ret.libc_base), "\n");

					return ret;
				}
				// _puts(_strncmp_no_strict("55", &buf[i], 2), 1);
		}
	}

	return RET_ME_ERR(-1);
}


static void _read(int fd, char *buff, size_t len) {
	asm("syscall" : : "a"(SYS_READ), "D"(fd), "S"(buff), "d"(len));
}

static void _munmap(char *addr, int sz) {
	asm("syscall" : : "a"(SYS_MUNMAP), "D"(addr), "S"(sz));
}

static ret_me get_libc_base() {
	int number = 0;
	int mfd = _open("/proc/self/maps", 0655);
	if (mfd < 0)
		DIE("[-] Error - cannot open /proc/self/maps - EXITTING\n");

	char *buf = (char *)_mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	long ret;

	// Read 0x1000b at (0x1000 -100)b blocks, to avoid libc being split
	// 30 block limit
	for (int i = 0; i < 30; i++) {
		asm("syscall" : "=a"(ret) : "a"(SYS_LSEEK), "D"(mfd), "S"(number), "d"(0));
		if (ret == -1) {
			DEBUG("[-] ERROR @", (char*)__FUNCTION__, "\n");
			return RET_ME_ERR(-1);
		}

		_read(mfd, buf, 0x1000);

		ret_me base = find_libc_base(buf);
		if (base.libc_base != -1) {
			myclose(mfd);
			_munmap(buf, 0x1000);
			return base;
		}

		number += 0x1000-100;
	}
	DEBUG("[!] Failed to find libc.so\n");
	return RET_ME_ERR(-1);
}


static void stick_in_ya_64(void *dest_ptr, void *src_ptr) {
	uintptr_t dest = (uintptr_t) dest_ptr;
	uintptr_t src = (uintptr_t) src_ptr;
	for (int n = 8; n > 0; n--) {
		unsigned char c = ((uintptr_t)src >> (64-n*8));// & ~(0xffffffffffffffff >> 64+8-n*8);
		// *((unsigned char*)(dest)+8-n) = c;	
		*((unsigned char*)(dest)+8-n) = c;
	}
}





void reloc_sym(char *main, Elf64_Sym *m_dynsym, char *m_dynstr, uint64_t r_offset, uint64_t r_info, uint64_t r_addend, char *libc, elf_t *libc_elf)
{
	// check for rela names in my bins symtab value eq dyntab value eq rela value
	// if not use libc if libc doesn't use my bins or JUST ERROR
	char *r_name = m_dynstr + m_dynsym[ELF64_R_SYM(r_info)].st_name;

	// Check for it being in Main bins dynsym
	Elf64_Sym *curr_sym = &m_dynsym[ELF64_R_SYM(r_info)];

	if (curr_sym->st_value != 0x0) {
		DEBUG("+++++self_sym++++\t\t");
		switch(ELF64_R_TYPE(r_info)) {
				case R_X86_64_JUMP_SLOT:
				case R_X86_64_GLOB_DAT:
					stick_in_ya_64(main+r_offset, main+curr_sym->st_value);
					DEBUG("Relocating ", r_name, " @ ", P_HEX64((unsigned long)(main+curr_sym->st_value)), "\n");
					break;
		}
	} else {
		// Find the libc symbol name
		for (int l = 0; l < (libc_elf->dynsym.sec->sh_size/sizeof(Elf64_Sym)); l++) {
			char *l_name = libc_elf->dynsym.str + libc_elf->dynsym.sym[l].st_name;

			if (_strncmp(r_name, l_name, _len(r_name)) == 0) {
				// DEBUG(">>>+~++~++~+~ RELOCATING from LIB_C ~+~++~++~+<<<\n");
				DEBUG("~=-=~=--LIBC-sym--=~=-=~\t", l_name, " ");

				switch (ELF64_R_TYPE(r_info)) {
					case R_X86_64_JUMP_SLOT:
					case R_X86_64_GLOB_DAT:
						if (ELF64_ST_TYPE(libc_elf->dynsym.sym[l].st_info) == STT_GNU_IFUNC) {
							long ret;

							DEBUG("It is an IFUNC - @ ", P_HEX64(libc_elf->dynsym.sym[l].st_value), "\n");

							asm("call *%0" : "=a"(ret) :"g"(libc+libc_elf->dynsym.sym[l].st_value));
										
							DEBUG("~  ", P_HEX64(ret), "\n");
							stick_in_ya_64(main+r_offset, (void*)ret);

						} else {
							DEBUG("~ ", P_HEX64((unsigned long)(libc+libc_elf->dynsym.sym[l].st_value)), "\n");
							stick_in_ya_64(main+r_offset, (void*)(libc+libc_elf->dynsym.sym[l].st_value));
						}
						break;
				}
			}
		}
	}
}



static void reloc_layer(char *main, Elf64_Sym *m_dynsym, char *m_dynstr, Elf64_Rela *m_rela, Elf64_Rel *m_rel, char *libc, elf_t *libc_elf) {
	// Elf64_Rel *m_rel 	= (Elf64_Rel *) (m_rel_addr);
	// Elf64_Rela *m_rela 	= (Elf64_Rela*) (m_rela_addr);
	// Elf64_Sym *m_dynsym = (Elf64_Sym *) (m_dynsym_addr);
			
	for (int j = 0; j < RELA_COUNT; m_rela++, j++) {

		if (ELF64_R_SYM(m_rela->r_info) != 0) {
			reloc_sym(main, m_dynsym, m_dynstr, m_rela->r_offset, m_rela->r_info, m_rela->r_addend, libc, libc_elf);
		}
	}
	
	// Rela
	for (int j = 0; j < REL_COUNT; m_rela++, j++) {

		if (ELF64_R_SYM(m_rel->r_info) != 0) {
			reloc_sym(main, m_dynsym, m_dynstr, m_rel->r_offset, m_rel->r_info, 0, libc, libc_elf);
		}
	}
}

static void parse_elf(char *memmap, elf_t *elf) {
	elf->memmap = memmap;
	elf->ehdr	= (Elf64_Ehdr*)memmap;
	elf->shdr	= (Elf64_Shdr*)(memmap+elf->ehdr->e_shoff);
	elf->shstrtab = (Elf64_Shdr*)(&elf->shdr[elf->ehdr->e_shstrndx]);
	elf->strtab = (char *)(memmap+elf->shstrtab->sh_offset);
	elf->phdr = (Elf64_Phdr*)(memmap+elf->ehdr->e_phoff);

	get_dynsym(elf);
}

static char *map_file(size_t *ret_size, char *file, int protections, int fixed, size_t base) {
	char *ret_map;
	// _puts("\nNEIN\nNEIN\nNEIN\n\n\n\n\n", 20);
	int fd = __syscall_3_x86_64(SYS_OPEN, (long int)file, 0, 0655);
	if (fd < 0) {
		DEBUG("[---] ERROR mapping file - ", file, "\n");
		asm("syscall" : : "a"(SYS_EXIT), "D"(-1));
	}
	// return;
	struct stat fstats;
	asm("syscall" : : "a"(SYS_FSTAT), "D"(fd), "S"(&fstats));
	unsigned long size = (unsigned long)fstats.st_size;

	if (fixed == 1) {
		ret_map = (char *)_mmap((void*)base, size, protections, MAP_PRIVATE | MAP_FIXED, fd, 0);
	} else {
		ret_map = (char *)_mmap(0, size, protections,
				MAP_PRIVATE, fd, 0);
	}	
	myclose(fd);

	DEBUG("[+] mmaped ", file, " @ ", P_HEX64((unsigned long)ret_map), "\n");

	*ret_size = size;
	return ret_map;
}



/**
 *
 */
static char *map_loadable_layer0(size_t *size) {
	Elf64_Phdr *phdr = data_section.phdr;
	// char *seg_mmap[PHDR_COUNT];
	DEBUG("----------Hello\n", P_HEX64(PHDR_COUNT));

	size_t prev = 0;
	size_t length =	phdr[PHDR_COUNT-1].p_vaddr + phdr[PHDR_COUNT-1].p_memsz - PAGE_ALIGN_DOWN(phdr[0].p_vaddr);
	*size = length;

	// Create the mapping for the L0
	char *bin_map = (char *)_mmap(0, length,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1, 0);

	// Map each PT_LOAD phdr -
	for (int i = 0; i < PHDR_COUNT; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			char *x = (char *)_mmap(bin_map + PAGE_ALIGN_DOWN(phdr[i].p_vaddr),
											PAGE_ALIGN((phdr[i].p_vaddr & 0xfff) + phdr[i].p_memsz),
											PROT_EXEC | PROT_READ | PROT_WRITE,
											MAP_PRIVATE | MAP_FIXED | MAP_ANON,
											-1, PAGE_ALIGN_DOWN(phdr[i].p_offset));
			_memcpy(x, layer0+prev, (size_t)phdr[i].p_filesz);
			prev += phdr[i].p_filesz;
		}
	}

	return bin_map;
}




typedef int (*__libc_start_main_t_ret)( __libc_start_main_t lbsm,	int (*main) (int, char * *, char * *),
						int argc,
						char * * ubp_av,
						void (*init) (void),
						void (*fini) (void),
						void (*rtld_fini) (void),
						void (* stack_end));


int __libc_start_main(	int (*main) (int, char * *, char * *),
						int argc,
						char * * ubp_av,
						void (*init) (void),
						void (*fini) (void),
						void (*rtld_fini) (void),
						void (* stack_end))
{
	size_t libc_sz, map1_sz;
	elf_t libc_elf;

	DEBUG("==~+==~+ ROXY-STUB +~==+~==\n");
	DEBUG("[+] Address of main [", P_HEX64((unsigned long)main), "]\n");

	ret_me base = get_libc_base();
	if (base.libc_base == -1)
		return -1;

	// Map the payload binary - !~!~! Shall be inside this binary, Shall be protected!
	// char *libmain = map_layer0(&main_sz, PROT_READ | PROT_WRITE, 0, 0);
	// char *libmain = map_file(&main_sz, "/home/rax/Documents/GitHub/DONE/dynLD_Roxy/Panter/panter.so", PROT_READ, 0, 0);
	char *libmain = map_loadable_layer0(&map1_sz);
	char *libc = map_file(&libc_sz, base.libc, PROT_READ, 0, 0);

	/** Map the L0 binary at a fixed address
	 * +Stick it inbetween libc or ld code caves, or just mmap a page after a loaded library
	 * +or do it in Panter - make Panter vanish after GOT poisoning
	 */
	// char *libmain1 = map_loadable(&map1_sz, "/home/rax/Documents/GitHub/DONE/dynLD_Roxy/Panter/panter.so");


	// parse_elf(libmain, &libmain_elf);
	parse_elf(libc, &libc_elf);

	// Relocate main_elf @libmain1 with libc_elf @base.libc_base
	reloc_layer(libmain, data_section.dynsym, data_section.dynstr, data_section.rela, data_section.rel, (char*)base.libc_base, &libc_elf);
	// check_rela(libmain1, base.libc_base, &libmain_elf, &libc_elf);
	__libc_start_main_t libc_start_man = (__libc_start_main_t)(base.libc_base + find_sym_addr(&libc_elf, "__libc_start_main"));

	/* Unmap the libc and L0 bin maps */
	// asm("syscall" : : "a"(SYS_MUNMAP), "D"(libmain), "S"(main_sz));
	asm("syscall" : : "a"(SYS_MUNMAP), "D"(libc), "S"(libc_sz));

	DEBUG("[+] MUNmapped libc\n");

	DEBUG("===============================\n");
	DEBUG("[+] Running the L0 bin!\n\n\n\n\n\n\n\n\n\n\n");
	// typedef int (*hook)(int (*) (int, char **, char **), int );
	__libc_start_main_t_ret f = (__libc_start_main_t_ret)
								(((unsigned long)libmain)+data_section.info.entry);
	// asm("int3" : :);
	return f(libc_start_man, main, argc, ubp_av, init, fini, rtld_fini, stack_end);
// 	if (libc_start_man == -1)
// 		_puts("------------------------------------FUCK\n", 41);

	// asm("jmp *%0\n" : : "r"((unsigned long)(libmain+0x0000000000001478)));

	// asm("syscall" : : "a"(SYS_EXIT), "D"(0));
	// return 0xdead;
}

/**
 * 		## It is important for this to be at the end, - .metadata should not go after .data_layer
 */

static __attribute__((section(".metadata"))) data_tmp_t data_section;

static __attribute__((section(".data_layer"))) char layer0[PROTECTED_BINARY_SIZE];



// __attribute__((section(".base_offset"))) char base = "\x00";