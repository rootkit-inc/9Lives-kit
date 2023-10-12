#include <stdio.h>
#include <assert.h>

#ifndef _CRYPTOR_H
#include "../includes/raptor/packer.h"
#endif

// !~!~! ATTENTION ! .data_layer shall NOT have larger offset than .metadata
// @copy_into_stub_fd - rewrite the stub binary
// ~output 		- output filename
// ~stub_elf 	- (struct elf_struct*) - the processed stub
// ~orig_elf	- (struct elf_struct*) - the original binary to be embedded inside the stub ~output
// ~data_struct - data_tmp_t
// ~phnum 		- size of all the PT_LOAD phdrs
// ~phnum		- number of PT_LOAD phdrs
void copy_into_stub_fd(char *output, struct elf_struct *stub_elf, struct elf_struct *orig_elf, data_tmp_t *data_struct, int phnum, size_t size) {
	size_t 		stub_offset = 0;
	// error_t err;
	Elf_Shdr *metadata = find_section_by_name(stub_elf, ".metadata");
	Elf_Shdr *layer0 = find_section_by_name(stub_elf, ".data_layer");
	if (metadata == (Elf_Shdr *)0xdeadbeef || layer0 == (Elf_Shdr *)0xdeadbeef)
		DIE("[-] Error While Finding .matadata OR .data_layer");

	// Copy FROM base TO .metadata
	memcpy(output, stub_elf->memmap, stub_elf->orig_size);
	memset(output + metadata->sh_offset, 0, metadata->sh_size);
	memset(output + layer0->sh_offset, 0, layer0->sh_size);

	// COPY into .data_layer
	move_PT_LOAD_phdrs(output, orig_elf, data_struct, layer0->sh_offset, phnum, layer0->sh_size);

	data_struct->info.entry = find_symbol_by_name(orig_elf, ENTRY_POINT_NAME);
	data_struct->info.e_phnum = count_PT_LOAD(orig_elf);
	
	// COPY the data_tmp_info info
	memcpy(output + metadata->sh_offset, &data_struct->info, sizeof(data_tmp_info));
	stub_offset+=metadata->sh_offset+sizeof(data_tmp_info);

	// COPY the phdr
	for (int i = 0; i < phnum; i++) {
		memcpy(output + stub_offset, &data_struct->phdr[i], sizeof(Elf64_Phdr));
		stub_offset+=sizeof(Elf64_Phdr);
	}

	// COPY Dynamic Symbols, RELA, REL, String table
	// these are needed for runtime relocation in Roxy-Stub
	COPY_SECTION(orig_elf, output, stub_offset, SHT_DYNSYM, ".dynsym", 0);
	COPY_SECTION(orig_elf, output, stub_offset, SHT_RELA, "\x00", COPY_ALL);
	COPY_SECTION(orig_elf, output, stub_offset, SHT_REL, "\x00", COPY_ALL);
	COPY_SECTION(orig_elf, output, stub_offset, SHT_STRTAB, ".dynstr", 0);
	// memset(output+stub_offset, 'B', metadata->sh_size - stub_offset);
	// stub_offset +=metadata->sh_size-stub_offset;

	// assert there is not an overflow
	printf("0x%lx ... 0x%lx\n", stub_offset-metadata->sh_offset, metadata->sh_size);
	assert(stub_offset-metadata->sh_offset <= metadata->sh_size);
	if ((phnum*sizeof(Elf64_Phdr) + sizeof(data_tmp_info)) > metadata->sh_size)
		DIE("data_tmp_t larger than .metadata %i + %i > %i", phnum*sizeof(Elf64_Phdr), sizeof(data_tmp_info), metadata->sh_size);

	// if (err.num != ALL_GOOD) {
	// 	DIE("[-] ERROR : %s\n", err.msg);
	// }
	// COPY the rest
	// memcpy(output + stub_offset, stub_elf->memmap + stub_offset, (size_t)(stub_elf->orig_size - stub_offset));
}

// @implant_into_stub - open the stub binary and call @copy_into_stub_fd
error_t implant_into_stub(struct elf_struct *stub_elf, struct elf_struct *orig_elf, char *stub_file, data_tmp_t *data_struct, int phnum, size_t size) {
	Elf_Shdr 	current;
	// size_t stub_elfsswswsw->orig_size = size+phnum*sizeof(data_tmp_t);

	int fd = open(stub_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IXUSR);
	if (fd == -1)
		return NEW_ERROR(OPEN_FAILED, "While Opening %s", stub_file);

	// data_struct->info.entry = orig_elf->ehdr->e_entry;
	// data_struct->phdr_metadata[0].offset = 0xcafecafe;
	// // data_tmp.shdr_metadata[1].real_offset = 0xdeadbeef;
	// for (int i = 0; i < 20; i++)
	// 	data_struct->crypted_layer0[i] = '\x41';

	// alloc sizeof template stub, size of tailored data_tmp_t counted
	unsigned char *output = (unsigned char *) mmap(0, stub_elf->orig_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	memset(output, 0, size*sizeof(unsigned char));

	// printf("%lx/%i MMAP SIZE\n", stub_elf->orig_size, stub_elf->orig_size);
	
	copy_into_stub_fd(output, stub_elf, orig_elf, data_struct, phnum, size);
	write(fd, output, stub_elf->orig_size);
	printf("[+] Packed binary written into stub \"%s\"\n", stub_file);
	
	munmap(output, stub_elf->orig_size);
	close(fd);

	return NEW_ERROR(ALL_GOOD, "");
}


// @get_all_PT_LOAD - returns count of PT_LOAD segments
//					And puts
int get_all_PT_LOAD(data_tmp_t *data_struct, struct elf_struct *orig_elf) {
	Elf_Phdr current;
	int nmemb = 1;
	int ndx = 0;

	for (int i = 0; i < orig_elf->ehdr->e_phnum; i++) {
		current = orig_elf->seg.phdr[i];
		if (current.p_type == PT_LOAD) {	// current.p_type == PT_INTERP
			data_struct->phdr = realloc(data_struct->phdr, nmemb*sizeof(Elf64_Phdr));
			nmemb++;

			memcpy(&data_struct->phdr[ndx], &current, sizeof(Elf_Phdr));
			ndx++;
		}
	}
	printf("[+] %i PT_LOAD segments to copy\n", ndx);


	data_struct->rel_n 		= orig_elf->rel.num;
	data_struct->rela_n 	= orig_elf->rela.num;
	data_struct->dynsym_n	= orig_elf->dyn.symnum;
	data_struct->dynstr_sz	= get_section_size(orig_elf, ".dynstr");

	return ndx;
}

// void x(data_tmp_t **data) {
// 				((*data)->phdr_metadata)[0].offset	= 0x43434343;
// }

// @move_PT_LOAD_phdrs - Copy into output
// ~output 		- mmap
// ~target_elf 	- original binary to be protected (struct elf_struct*)
// ~offset 		- offset to crypted_layer0
// ~max 		- shall not be exceeded
void move_PT_LOAD_phdrs(char *output, struct elf_struct *target_elf, data_tmp_t *data_struct, size_t offset, size_t nmemb, size_t max) {
	Elf_Phdr current;
	size_t prev = 0;
	// size_t orig_entry = (size_t)target_elf->ehdr->e_entry;
	// size_t entry = orig_entry;

	for (int i = 0; i < target_elf->ehdr->e_phnum; i++) {
		current = target_elf->seg.phdr[i];
		// Dont include anything that in the Program Header Table that is NOT PT_LOAD (or PT_INTERP)
		// + This packer is only for .so (shared objects), PT_INTERP IS NOT NEEDED
		if (current.p_type == PT_LOAD || current.p_type == PT_INTERP) {
			memcpy(output + ((size_t)offset)+prev, target_elf->memmap + current.p_offset, current.p_filesz);
			
			// Remove of anything in PT_PHDR segment that is not necessary
			// first phdr - PT_PHDR
			if (current.p_offset == 0 && current.p_filesz > target_elf->ehdr->e_phoff) {
				size_t size_of_mmap = target_elf->ehdr->e_phnum*sizeof(Elf_Phdr);
				// char *tmp_mmap = (char*)mmap(0, size_of_mmap,
				// 										PROT_READ | PROT_WRITE,
				// 										MAP_PRIVATE | MAP_ANONYMOUS,
				// 										-1, 0);
				// +might selectively remove phdrs
				// memcpy(tmp_mmap, target_elf->seg.phdr, size_of_mmap);
				// Elf_Phdr *out_phdr = (Elf_Phdr *)tmp_mmap;

				assert(size_of_mmap <= current.p_filesz - target_elf->ehdr->e_phoff);
				// Null the PHDR
				memset(output + ((size_t)offset)+prev+target_elf->ehdr->e_phoff, 0, size_of_mmap);
			}

			prev += current.p_filesz;

			// printf("[+] PREV 0x%lx, MAX 0x%lx\n", prev, max);
			assert(prev <= max);
		}
	}

	// printf("%lx- %lx \n", prev, max);
	// assert(prev == max);
	// puts("kkkkkkkkkkk");
	// return entry;
}


// @parse_the_stub
// ~stub - elf_struct to parse into - a cheap way to avoid malloc's (forgotten) free
// ~stub_file - name of the file to parse, the output of gcc @create_stub_file
// [WARNING] - WILL BE USELESS / SEMI-USELESS / size phnum shall not be the size of the original file - -
error_t parse_the_stub(struct elf_struct *stub, char *stub_filename) {
	struct error_t err;

	err = new_load_elf(stub_filename, stub);
	if(err.num != ALL_GOOD)
		return err;

	check_elf_magic(stub);
	process_phdrs(stub);
	process_sections(stub);

	return NEW_ERROR(ALL_GOOD, "");
}


// Different function - how else would remake the array size without malloc
data_tmp_t *create_stub_struct(size_t size, int nmemb) {
	data_tmp_t *data_tmp = malloc(sizeof(data_tmp_t));
	data_tmp->phdr = malloc(nmemb*sizeof(Elf64_Phdr));
	// twice the size of 25600 bytes is too much 
	// data_tmp->crypted_layer0 = (char *)mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(&data_tmp->info, 0, sizeof(data_tmp_info));
	memset(data_tmp->phdr, 0, nmemb*sizeof(Elf64_Phdr));

	// memset(data_tmp->crypted_layer0, 0, size*sizeof(char));

	return data_tmp;
}

// free() the data_tmp_t
void free_stub_struct(data_tmp_t *data_struct, size_t size) {
	free(data_struct->phdr);
	// munmap(data_struct->crypted_layer0, size);
	free(data_struct);
}

// gcc -nostdlib ./roxy_stub.c ./stub.h -o TESTING -D PROTECTED_BINARY_SIZE=10 -D SECTION_COUNT=20

// @create_stub_template_file - compile stub
// ~stub_output - output filename
// ~stub_input 	- input source filename
// ~orig_size 	- size of all the PT_LOAD phdrs
// ~phnum 		- number of PT_LOAD phdrs
int create_stub_template_file(data_tmp_t *data_struct, char *stub_output, char *stub_input, size_t orig_size, size_t phnum, struct elf_struct *orig) {
	char binsize[50], sec_count[50], rel_count[50], rela_count[50], dynstr_count[50], dynsym_count[50];
	int err = 0;

	// It is ugly, but it is sufficient and works
	snprintf(binsize, 50, "PROTECTED_BINARY_SIZE=%lu\x00", orig_size);
	snprintf(sec_count, 50, "PHDR_COUNT=%i\x00", phnum);
	snprintf(rel_count, 50, "REL_COUNT=%i\x00", data_struct->rel_n);
	snprintf(rela_count, 50, "RELA_COUNT=%i\x00", data_struct->rela_n);
	snprintf(dynstr_count, 50, "DYNSYM_COUNT=%i\x00", data_struct->dynsym_n);
	snprintf(dynsym_count, 50, "DYNSTR_LEN=%i\x00", data_struct->dynstr_sz);

	printf("[+] Compiling the stub:\n");
	// printf("=+++++++++++ REL %i ; RELA %i ; DYNSYM %i ; STRLEN %i\n\n\n\n\n", data_struct->rel_n, data_struct->rela_n, data_struct->dynsym_n, data_struct->dynstr_sz);

	int child = fork();
	if (child == 0) {
		// gcc -c ./main.c -fPIC -nostdlib -shared -Wall -o stub.so
		execl(GCC, GCC, stub_input, "-fPIC", "-shared", "-nostdlib", "-Wdangling-pointer=0", "-o", stub_output,
			"-D", (const char*)binsize,
			"-D", (const char*)sec_count,
			"-D", (const char*)rel_count,
			"-D", (const char*)rela_count,
			"-D", (const char*)dynstr_count,
			"-D", (const char*)dynsym_count, NULL);
		// execl(GCC, GCC, "-c", "-nostdlib", stub_input, "-o", stub_output, "-D", (const char*)binsize, "-D", (const char*)sec, "-g", NULL);
	} else {
		int status;
		while (1) {
			waitpid(child, &status, 0);
			if (WIFEXITED(status)) break;
			if (WIFSIGNALED(status)) {
				err = -1;
				break;
			}
		}
	}

	printf("[+] This program will continue even if you see errors\n");

	return err;
}
