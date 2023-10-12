/* This file defines standard ELF types, structures, and macros.
   Copyright (C) 1995-2022 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

// * typedefs from elf.h have been copied & modified


#ifndef RAPTOR_PACKER
	#define EI_NIDENT (16)

	typedef unsigned long size_t;
	typedef unsigned long long uint64_t;
	typedef unsigned long uintptr_t;
	typedef unsigned long off_t;
	typedef unsigned int uint32_t;
	typedef unsigned short uint16_t;

	typedef struct
	{
	  uint32_t	sh_name;		/* Section name (string tbl index) */
	  uint32_t	sh_type;		/* Section type */
	  uint64_t	sh_flags;		/* Section flags */
	  uint64_t	sh_addr;		/* Section virtual addr at execution */
	  uint64_t	sh_offset;		/* Section file offset */
	  uint64_t	sh_size;		/* Section size in bytes */
	  uint32_t	sh_link;		/* Link to another section */
	  uint32_t	sh_info;		/* Additional section information */
	  uint64_t	sh_addralign;		/* Section alignment */
	  uint64_t	sh_entsize;		/* Entry size if section holds table */
	} Elf64_Shdr;

	typedef struct
	{
	  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
	  uint16_t	e_type;			/* Object file type */
	  uint16_t	e_machine;		/* Architecture */
	  uint32_t	e_version;		/* Object file version */
	  uint64_t	e_entry;		/* Entry point virtual address */
	  uint64_t	e_phoff;		/* Program header table file offset */
	  uint64_t	e_shoff;		/* Section header table file offset */
	  uint32_t	e_flags;		/* Processor-specific flags */
	  uint16_t	e_ehsize;		/* ELF header size in bytes */
	  uint16_t	e_phentsize;		/* Program header table entry size */
	  uint16_t	e_phnum;		/* Program header table entry count */
	  uint16_t	e_shentsize;		/* Section header table entry size */
	  uint16_t	e_shnum;		/* Section header table entry count */
	  uint16_t	e_shstrndx;		/* Section header string table index */
	} Elf64_Ehdr;


	typedef struct {
		uint32_t	p_type;
		uint32_t	p_flags;
		uint64_t 	p_offset;
		uint64_t	p_vaddr;
		uint64_t	p_paddr;
		uint64_t	p_filesz;
		uint64_t	p_memsz;
		uint64_t	p_align;
	} Elf64_Phdr;

	#define SHT_RELA	  4		/* Relocation entries with addends */
	#define SHT_REL		9
	#define SHT_DYNSYM	  11		/* Dynamic linker symbol table */
	#define SHT_SYMTAB	  2		/* Symbol table */


	#define AT_PHDR   3	/* program headers for program */
	#define AT_PHNUM  5	/* number of program headers */
	#define AT_BASE   7	/* base address of interpreter */
	#define AT_ENTRY  9	

	#define PT_LOAD		1		/* Loadable program segment */

	#define R_X86_64_GLOB_DAT 6 /* Create GOT entry */
	#define R_X86_64_JUMP_SLOT  7 /* Create PLT entry */


	#define ELF64_R_SYM(i)			((i) >> 32)
	#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
	#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))


	typedef struct
	{
	  uint64_t	r_offset;		/* Address */
	  uint64_t	r_info;			/* Relocation type and symbol index */
	  uint64_t	r_addend;		/* Addend */
	} Elf64_Rela;
	
	typedef struct
	{
	  uint64_t	r_offset;		/* Address */
	  uint64_t	r_info;			/* Relocation type and symbol index */
	} Elf64_Rel;

	#define STT_GNU_IFUNC 10    /* Symbol is indirect code object */

	#define ELF_ST_TYPE(x)    ((x) & 0xf)
	#define ELF64_ST_TYPE(x)  ELF_ST_TYPE(x)

	typedef struct
	{
	  uint32_t	st_name;		/* Symbol name (string tbl index) */
	  unsigned char	st_info;		/* Symbol type and binding */
	  unsigned char st_other;		/* Symbol visibility */
	  uint16_t	st_shndx;		/* Section index */
	  uint64_t	st_value;		/* Symbol value */
	  uint64_t	st_size;		/* Symbol size */
	} Elf64_Sym;
#endif

//
//
#ifndef RAPTOR_PACKER
	typedef struct {
		Elf64_Shdr *sec;
		Elf64_Sym *sym;
		char *str;
	} symtab_tuple;

	typedef struct {
		char 			*memmap;
		Elf64_Ehdr	*ehdr;
		Elf64_Shdr	*shdr;
		Elf64_Shdr	*shstrtab;
		Elf64_Phdr	*phdr;
		char 		*strtab;
		symtab_tuple 	dynsym;
		symtab_tuple 	symtab;

		Elf64_Rela	*rela;
	} elf_t;
#endif

typedef struct {
	unsigned long entry;
	unsigned long phoff;
	unsigned long e_phnum;
} data_tmp_info;

typedef struct {
	data_tmp_info 	info;
		#ifdef RAPTOR_PACKER
			Elf64_Phdr 		*phdr;
			Elf64_Sym 		*dynsym;				//
			Elf64_Rela		*rela;					//
			Elf64_Rel   	*rel;					//
			char 			*dynstr;
			int dynsym_n;
			int rela_n;
			int rel_n;
			int dynstr_sz;
		#else
			Elf64_Phdr 		phdr[PHDR_COUNT];
			Elf64_Sym 		dynsym[DYNSYM_COUNT];	//
			Elf64_Rela		rela[RELA_COUNT];		//
			Elf64_Rel   	rel[REL_COUNT];			//
			char  			dynstr[DYNSTR_LEN];
		#endif
} data_tmp_t;