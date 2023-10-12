#ifndef _ELF_HELPER
#define _ELF_HELPER
#endif

#ifndef _ERROR_H
#include "./error.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

// I have absolutely no clue why it works with a wrong ARCH##n set when it is compiled with -m32 and vice versa
// Not anymore! You get a segfault!
#define ARCH64

// The lazy way of doing it
#define DEBUG(msg, ...) do { /*NOTHING*/ } while (0)
// #define DEBUG(msg, ...) (fprintf(stderr, msg, ##__VA_ARGS__))

#define FORCE_CORRECT_GOT		// make .got from .got.plt


#ifdef ARCH64
	#define Elf_Ehdr Elf64_Ehdr
	#define Elf_Phdr Elf64_Phdr
	#define Elf_Shdr Elf64_Shdr
	#define Elf_Sym  Elf64_Sym
	#define Elf_Dyn  Elf64_Dyn
	#define Elf_Rela Elf64_Rela
	#define Elf_Rel Elf64_Rel
	#define Elf_Off  Elf64_Off
	#define Elf_Addr Elf64_Addr
	#define ELF_R_SYM ELF64_R_SYM
#elif defined ARCH32
	#define Elf_Ehdr Elf32_Ehdr
	#define Elf_Phdr Elf32_Phdr
	#define Elf_Shdr Elf32_Shdr
	#define Elf_Sym  Elf32_Sym
	#define Elf_Dyn  Elf32_Dyn
	#define Elf_Rela Elf32_Rela
	#define Elf_Rel Elf32_Rel
	#define Elf_Off  Elf32_Off
	#define Elf_Addr Elf32_Addr
	#define ELF_R_SYM ELF32_R_SYM
#endif


#define SHT_X_COUNT(elf, SHT) do {								\
			int counter = 0;										\
			for (int i = 0; i < elf->ehdr->e_shnum; i++) {			\
				if (elf->sec.shdr[i].sh_type == SHT)			\
					counter++;										\
			}														\
			counter;												\
}

// Borrowed from my other project
#define SAVE_PHDR_DATA(elf, entry, index) do {							\
			elf->seg.entry.phdr		= elf->seg.phdr[index];				\
			elf->seg.entry.p_paddr	= elf->seg.phdr[index].p_paddr;		\
			elf->seg.entry.p_vaddr	= elf->seg.phdr[index].p_vaddr;		\
			elf->seg.entry.p_offset	= elf->seg.phdr[index].p_offset;	\
			elf->seg.entry.p_filesz	= elf->seg.phdr[index].p_filesz;	\
					} while(0)

typedef struct segment {
	Elf64_Phdr 	phdr;
	Elf64_Addr	p_vaddr;
	Elf64_Addr	p_paddr;
	Elf64_Off	p_offset;
	uint64_t	p_filesz;
} segment;
// =========END====

typedef struct sym_tuple {
	int 		index;
	char 		*name;
	Elf_Off 	offset;
} sym_tuple;

struct elf_struct{
	char 	*memmap;
	int 	fd;
	size_t	orig_size;
	int 	arch;
	Elf_Ehdr *ehdr;
	int 	relath_ith;
	struct seg {
		Elf_Phdr 		*phdr;
		segment			dynamic;
		segment			text;
		segment			data;
	} seg;
	struct sec {
		struct parts {
			Elf_Shdr	got_plt;
		} parts;
		Elf_Shdr 	*shdr;
		Elf_Shdr 	*shdrtbl_sec;
		char 		*shdrtbl_str;
	} sec;
	struct dyn {
		int 		symnum;
		Elf_Shdr 	shdr;
		Elf_Dyn 	*dynamic;
		Elf_Sym 	*dynsym_tab;
		sym_tuple   *symbols;
		char		*dynsym_str;
	} dyn;
	struct sym {
		int 		symnum;
		Elf_Shdr 	shdr;
		Elf_Sym 	*sym_tab;
		char 		*sym_str;
	} sym;
	Elf_Addr got_addr;

	struct rel {
		int 		num;
	// 	Elf_Sym 	*sym_tab;
	// 	Elf_Rela 	*rel;
	// 	char 		*str_tab;
	} rel;
	struct rela {
		int num;
	} rela;
};

struct error_t new_load_elf(const char *, struct elf_struct *);
int check_elf_magic(struct elf_struct *);
void process_phdrs(struct elf_struct *);
void process_sections(struct elf_struct *);
uintptr_t get_got_addr(struct elf_struct*);
void get_rela_plt_offsets(struct elf_struct *);
void remove_shstrtab(struct elf_struct *);
int count_PT_LOAD(struct elf_struct *);
int get_section_size(struct  elf_struct *, char *);
unsigned long find_symbol_by_name(struct elf_struct *, char *);
Elf_Shdr *find_section_by_name(struct elf_struct *, char *);
void *wassup(void *, size_t , int , int , int , off_t );