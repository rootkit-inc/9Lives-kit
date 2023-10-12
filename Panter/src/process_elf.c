#ifndef _ELF_HELPER
#include "../../includes/elf.h"
#endif


error_t new_load_elf(const char *target_file, struct elf_struct *self_elf) {
	struct stat fstat_info;
	error_t err;

	// get stats of target_file for its st_size

	self_elf->fd = open(target_file, O_RDONLY);
	if (self_elf->fd == -1) {
		err = NEW_ERROR(OPEN_FAILED, "[-] Couldn't open %s\n", target_file);
		return err;		// Check if self_elf->fd == -1, in callee function
	}

	fstat(self_elf->fd, &fstat_info);
	self_elf->orig_size = (size_t) fstat_info.st_size;
// add failed to elf_struct to replace == -1 || == NUll. move DEBUG to .h
	self_elf->memmap = (char*) mmap(0, self_elf->orig_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, self_elf->fd, 0);
	if (self_elf->memmap == NULL) {
		err = NEW_ERROR(MMAP_FAILED, "[-] MMAP FAILED\n");
		return err;
	}

	close(self_elf->fd);
	err.num = ALL_GOOD;
	return err;
}


int check_elf_magic(struct elf_struct *self_elf) {
	self_elf->ehdr = (Elf_Ehdr *) self_elf->memmap;

	if (self_elf->ehdr->e_ident[EI_MAG0] == '\x7f' && self_elf->ehdr->e_ident[EI_MAG1] == 'E' &&
		self_elf->ehdr->e_ident[EI_MAG2] == 'L' && self_elf->ehdr->e_ident[EI_MAG3] == 'F') {
		return 0;
	}
	return -1;
}

//
// Find GOT offset, find first page in the program and add the founf GOT offset to it 
// WORKS ON 64bit only because of 0x2000 pages
Elf_Addr get_got_addr(struct elf_struct *self_elf) {
	Elf_Addr got_addr;
	Elf_Shdr current;

	for (int i = 0; self_elf->dyn.dynamic[i].d_tag != DT_NULL; i++) {
		if (self_elf->dyn.dynamic[i].d_tag == DT_PLTGOT) {
			got_addr = (Elf_Addr) self_elf->dyn.dynamic[i].d_un.d_val;
		}
	}

	#ifdef FORCE_CORRECT_GOT
		if (self_elf->sec.parts.got_plt.sh_size > 0) {
			for (int l = 0; l < self_elf->ehdr->e_shnum; l++) {
				current = self_elf->sec.shdr[l];
				if (strcmp(&self_elf->sec.shdrtbl_str[current.sh_name], ".got") == 0) {
					DEBUG("[+] Correcting got_addr from .got.plt to .got\n");
					got_addr = got_addr - (self_elf->sec.parts.got_plt.sh_offset - current.sh_offset);
				}
			}
		}
	#endif
	return got_addr;
}

void process_phdrs(struct elf_struct *self_elf) {
	self_elf->seg.phdr = (Elf_Phdr *) (self_elf->memmap + self_elf->ehdr->e_phoff);
	for (int i = 0; i < self_elf->ehdr->e_phnum; i++) {
		if (self_elf->seg.phdr[i].p_type == PT_DYNAMIC) {
			self_elf->dyn.dynamic = (Elf_Dyn *) (self_elf->memmap + self_elf->seg.phdr[i].p_offset);
			SAVE_PHDR_DATA(self_elf, dynamic, i);
			DEBUG("DYNAMIC offset @0x%lx\n", self_elf->seg.dynamic.p_offset);
			continue;
		}
		if (self_elf->seg.phdr[i].p_type == PT_LOAD
			// && self_elf->seg.phdr[i].p_flags == PF_R | PF_X
			// == PF_R ok, == PF_X no, .text should be RX 
			&& !self_elf->seg.phdr[i].p_offset) {
			// HIT .text segment
			SAVE_PHDR_DATA(self_elf, text, i);
			DEBUG("TEXT memsz @0x%lx\n", self_elf->seg.phdr[i].p_memsz);
			continue;
		}
		if (self_elf->seg.phdr[i].p_type == PT_LOAD && !!self_elf->seg.phdr[i].p_offset) {
			// (self_elf->seg.text.p_offset != 0) ? (self_elf->seg.phdr[i].p_offset > self_elf->seg.text.p_offset) : 0) {
			DEBUG("\t\t\t\t\t\t@0x%lx YUP!!!!!\n", self_elf->seg.phdr[i].p_memsz);
			continue;
		}
	}
}


void process_sections(struct elf_struct *self_elf) {
	Elf_Shdr current;
	self_elf->sec.shdr = (Elf_Shdr *) (self_elf->memmap + self_elf->ehdr->e_shoff);
	self_elf->sec.shdrtbl_sec = (Elf_Shdr *) (&self_elf->sec.shdr[self_elf->ehdr->e_shstrndx]);
	self_elf->sec.shdrtbl_str = (char *) (self_elf->memmap + self_elf->sec.shdrtbl_sec->sh_offset);

// 	// [vdso] loaded by kernel @load_elf_binary
// 	// size 0x2000 r-x
// 	// 64 - AFTER 0x00007ffff7f00000	(0x7ffff7fc9000)
// 	// 32 - AFTER 0xf7f00000 			(0xf7fc7000)

	for (int i = 0; i < self_elf->ehdr->e_shnum; i++) {
		current = self_elf->sec.shdr[i];
		DEBUG("Section number: %d, Name: %s, OFFSET: 0x%lx\n",
			i, &self_elf->sec.shdrtbl_str[current.sh_name], current.sh_offset);

		if (strcmp(&self_elf->sec.shdrtbl_str[current.sh_name], ".got.plt") == 0) {
			self_elf->sec.parts.got_plt = current;
		}
		switch (current.sh_type) {
		// case SHT_REL:
		case SHT_SYMTAB:		// * SYMBOL TABLE
			self_elf->sym.sym_tab = (Elf_Sym*) (self_elf->memmap + current.sh_offset);
			self_elf->sym.sym_str = (char *) (self_elf->memmap + self_elf->sec.shdr[current.sh_link].sh_offset);
			self_elf->sym.shdr = (Elf_Shdr) current;

			int l;
			for (l = 0; l < (current.sh_size / sizeof(Elf_Sym)); l++) {
				DEBUG("From [SHT_SYMTAB] > Symbol N#%i => NAME: [\"%s\"]\n", l,
					self_elf->sym.sym_str + self_elf->sym.sym_tab[l].st_name);
			}
			self_elf->sym.symnum = l+1;
			break;
		case SHT_DYNSYM:
			self_elf->dyn.dynsym_tab = (Elf_Sym *) (self_elf->memmap + current.sh_offset);
			self_elf->dyn.dynsym_str = (char *) (self_elf->memmap + self_elf->sec.shdr[current.sh_link].sh_offset);
			self_elf->dyn.shdr = current;
			int j;
			for (j = 0; j < (current.sh_size/sizeof(Elf_Sym)); j++) {
				DEBUG("Dynamic Symbol N#%i => NAME: [\"%s\"]\n", j,
					self_elf->dyn.dynsym_str + self_elf->dyn.dynsym_tab[j].st_name);
			}
			self_elf->dyn.symnum = j;
			break;
		case SHT_REL:
			self_elf->rel.num+=current.sh_size/sizeof(Elf_Rel);
			break;
		case SHT_RELA:
			self_elf->rela.num+=current.sh_size/sizeof(Elf_Rela);
			break;
		default:
			continue;
		}
	}
}


void get_rela_plt_offsets(struct elf_struct *self_elf) {
	Elf_Shdr current;
	int index = 0;
	
	self_elf->dyn.symbols = malloc(self_elf->dyn.symnum*sizeof(sym_tuple));
	for (int i = 0; i < self_elf->ehdr->e_shnum; i++) {
		current = self_elf->sec.shdr[i];

		if (current.sh_type == SHT_RELA) {
			// if (strcmp(&self_elf->sec.shdrtbl_str[current.sh_name], ".rela.plt") != 0)
				// continue;

			Elf_Rela *rela = (Elf_Rela *) (self_elf->memmap + current.sh_offset);
			for (int j = 0; j < (current.sh_size / sizeof(Elf_Rela)); rela++, j++) {
				if (ELF_R_SYM(rela->r_info) > self_elf->dyn.symnum)
					continue;

				// Elf_Sym *symbol = &self_elf->dyn.dynsym_tab[ELF_R_SYM(rela->r_info)];

				char *name = self_elf->dyn.dynsym_str + self_elf->dyn.dynsym_tab[ELF_R_SYM(rela->r_info)].st_name;
				if (strlen(name) == 0)
					continue;

				// DEBUG("[+] ith: %i symbol name: %s, offset: %lx\n",j, name, index);

				self_elf->dyn.symbols[index].index = ELF_R_SYM(rela->r_info);
				self_elf->dyn.symbols[index].offset = rela->r_offset;
				self_elf->dyn.symbols[index].name = name;
				index++;
			}
		}
	}
}

void remove_shstrtab(struct elf_struct *target_elf) {
	Elf_Shdr current;
	char *msg = "REMAIN_in_The_LIGHT";
	int str_i = 0;
	for (int i = 0; i < target_elf->ehdr->e_shnum; i++) {
		current = target_elf->sec.shdr[i];
		if (current.sh_type == SHT_DYNSYM) {

			for (int l = 0; l < (current.sh_size / sizeof(Elf_Sym)); l++) {
				char *symstr = &target_elf->dyn.dynsym_str[target_elf->dyn.dynsym_tab[l].st_name];

				for (int j = 0; j < strlen(symstr); j++) {
					*(symstr+j) = msg[str_i%19];
					str_i++;
				}
			}
		}
		if (current.sh_type == SHT_SYMTAB) {
			for (int l = 0; l < (current.sh_size / sizeof(Elf_Sym)); l++) {
				char *symstr = &target_elf->sym.sym_str[target_elf->sym.sym_tab[l].st_name];
				if (strncmp(symstr, "__libc_start_main", 17) == 0) {
					continue;				// !~!~! CONFIG
				}

				for (int j = 0; j < strlen(symstr); j++) {
					*(symstr+j) = msg[str_i%19];
					str_i++;
				}
			}
		}
	}
}

int count_PT_LOAD(struct elf_struct *elf) {
	int pt_num = 0;
	for (int i = 0; i < elf->ehdr->e_phnum; i++) {
		if (elf->seg.phdr[i].p_type == PT_LOAD)
			pt_num++;
	}
	return pt_num;
}

int get_section_size(struct  elf_struct *elf, char *sec_name) {
	for (int i = 0; i < elf->ehdr->e_shnum; i++) {
		if (strncmp(&elf->sec.shdrtbl_str[elf->sec.shdr[i].sh_name], sec_name, strlen(sec_name)) == 0) {
			return elf->sec.shdr[i].sh_size;
		}
	}
	return -1;
}

// int count_rela(struct elf_struct *elf) {
// 	for (int i = 0; i < elf->ehdr->e_shnum; i++) {
// 		if (elf->sec.shdr[i].sh_type == SHT_RELA) {
// 			return elf->sec.shdr[i].sh_size/sizeof(Elf_Rela);
// 		}
// 	}
// 	return -1;
// }

// int count_rel(struct elf_struct *elf) {
// 	for (int i = 0; i < elf->ehdr->e_shnum; i++) {
// 		if (elf->sec.shdr[i].sh_type == SHT_REL) {
// 			return elf->sec.shdr[i].sh_size/sizeof(Elf_Rel);
// 		}
// 	}
// 	return -1;
// }

// int count_dynsym(struct elf_struct *elf) {
// 	for (int i = 0; i < elf->ehdr->e_shnum; i++) {
// 		if (elf->sec.shdr[i].sh_type == SHT_DYNSYM) {
// 			return elf->sec.shdr[i].sh_size/sizeof(Elf_Sym);
// 		}
// 	}
// 	return -1;
// }

unsigned long find_symbol_by_name(struct elf_struct *elf, char *name) {
	for (int i = 0; i < (elf->sym.shdr.sh_size/sizeof(Elf_Sym)); i++) {
		if (strncmp(name, &elf->sym.sym_str[elf->sym.sym_tab[i].st_name], strlen(name)) == 0) {
			return (unsigned long)elf->sym.sym_tab[i].st_value;
		}
	}

	for (int i = 0; i < (elf->dyn.shdr.sh_size/sizeof(Elf_Sym)); i++) {
		if (strncmp(name, &elf->dyn.dynsym_str[elf->dyn.dynsym_tab[i].st_name], strlen(name)) == 0) {
			return (unsigned long)elf->dyn.dynsym_tab[i].st_value;
		}
	}
	
	return 0;
}


Elf_Shdr *find_section_by_name(struct elf_struct *elf, char *name) {
	for (int i = 0; i < elf->ehdr->e_shnum; i++) {
		if (strcmp(&elf->sec.shdrtbl_str[elf->sec.shdr[i].sh_name], name) == 0) {
			return &elf->sec.shdr[i];
		}
	}
	return (Elf_Shdr*) 0xdeadbeef;
}
