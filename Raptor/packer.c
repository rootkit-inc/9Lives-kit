#include <stdio.h>
#include <assert.h>

#ifndef _RAPTOR_ELF_H
#include "../includes/raptor/elf.h"
#endif

#ifndef _CRYPTOR_H
#include "../includes/raptor/packer.h"
#endif

#define RAPTOR_STRICTLY_CHECK_MAGIC
// #define KEY "Rax\xcc"
// #define KEY_SIZE 4 

// check_elf_magic is neccessary, use it in new_load_elf

int fulfill_stub(struct elf_struct *orig_elf, char *stub_file_c, char *stub_outputfile) {
	struct elf_struct stub_elf;
	error_t err;
	size_t alltogether = 0;
	size_t size_mmap = orig_elf->orig_size;

	data_tmp_t *data_struct = create_stub_struct(size_mmap, 1);	// Placeholder
	int nmemb = get_all_PT_LOAD(data_struct, orig_elf);

	for (int i = 0; i < nmemb; i++) {
		alltogether += data_struct->phdr[i].p_filesz;
	}
	if (create_stub_template_file(data_struct, stub_outputfile, stub_file_c, alltogether, nmemb, orig_elf))
		perror("!~!~! While Creating the stub template file");

	err = parse_the_stub(&stub_elf, stub_outputfile);
	if (err.num != ALL_GOOD) {
		fprintf(stderr, "[-] ERROR: @%s %s\n", __FUNCTION__, err.msg);		// Here it ends folks, 
		return -1;
	}

	// remove_shstrtab(&stub_elf);
	

	implant_into_stub(&stub_elf, orig_elf, stub_outputfile, data_struct, nmemb, alltogether);
	puts("DONE");

	free_stub_struct(data_struct, size_mmap);

	return 0;
}



int main(int argc, char *argv[]) {
	struct elf_struct target_elf;
	struct error_t err;

	// Will only work with Static and PIC bins
	fprintf(stdout, "~=*=*=~ [ Raptor ] ~=*=*~\n");

	if (argc < 2) {
		DIE("Usage: %s <path/filename>\n", argv[0]);
	}

	// load the ORIGINAL binary - protected bin
	err = new_load_elf(argv[1], &target_elf);
	if(err.num != ALL_GOOD)
		DIE("[-] NEW ERROR: %s\n", err.msg);

	#ifdef RAPTOR_STRICTLY_CHECK_MAGIC		// Won't work without check_elf_magic, because it'd be missing Elf_Ehdr
		int elf_mag = check_elf_magic(&target_elf);
		assert(elf_mag == 0);
	#endif

	// Parse Program headers & sections
	process_phdrs(&target_elf);
	process_sections(&target_elf);

	// Incomplete - What I need
	// only PT_LOAD, it's size, vaddr, offset
	size_t orig_size = target_elf.orig_size;
	size_t shnum 	 = target_elf.ehdr->e_shnum;


	// Compile the stub
	// if (create_stub_file(&target_elf, STUB_OUTPUT_FILENAME, orig_size, shnum) == -1)
	// 	DIE("@%s {YOU GOT ME FUCKED!}", __FUNCTION__);

	// remove_shstrtab(&target_elf);
	// if (err.num != ALL_GOOD)
	// 	DIE("[-] NEW ERROR: %s\n", err.msg);
	if (fulfill_stub(&target_elf, STUB_FILE, "./output/stub.so") == -1)
		DIE("[-] NEW ERROR: couldn't open stub file\n");

	return 0;
}