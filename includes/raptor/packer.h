#ifndef _CRYPTOR_H
#define _CRYPTOR_H
#endif

#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>

#define RAPTOR_PACKER

#define GCC "/usr/bin/gcc"
#define STUB_OUTPUT_FILENAME "./output/stub"
#define STUB_FILE "./Raptor-Stub/stub.c"

#define ENTRY_POINT_NAME "__libc_start_main"

#ifndef _ELF_HELPER
#include "../elf.h"
#endif

// #include "../includes/hexdump.h"
#ifndef _STUB_H
#include "../../Raptor/Raptor-Stub/elf.h"
#endif


#define COPY_ALL 0x12345678

#define COPY_SECTION(elf, output, offset, SHT, NAME, ith) ({	\
			int counter = 0;										\
			Elf64_Shdr sec;											\
			for (int i = 0; i < elf->ehdr->e_shnum; i++) {			\
				sec = elf->sec.shdr[i];								\
				if (sec.sh_type == (size_t)SHT) {					\
					if (*NAME == '\x00' || strcmp(NAME, &elf->sec.shdrtbl_str[sec.sh_name]) == 0) {	\
						if (counter == ith || ith == COPY_ALL) {	\
							printf("/%i\n", SHT);					\
							memcpy(output + offset, elf->memmap + sec.sh_offset, sec.sh_size);		\
							offset += sec.sh_size;					\
							if (ith != COPY_ALL) {					\
								break;								\
							}										\
						}											\
					}												\
				counter++;											\
				}													\
			}														\
})

void copy_into_stub_fd(char *, struct elf_struct *, struct elf_struct *, data_tmp_t *, int, size_t);
error_t implant_into_stub(struct elf_struct *, struct elf_struct *, char *, data_tmp_t *, int, size_t);
int get_all_PT_LOAD(data_tmp_t *, struct elf_struct *);
void move_PT_LOAD_phdrs(char *, struct elf_struct *, data_tmp_t *data_struct, size_t, size_t, size_t);
error_t parse_the_stub(struct elf_struct *, char *);
data_tmp_t *create_stub_struct(size_t size, int nmemb);
void free_stub_struct(data_tmp_t *data_struct, size_t size);
int create_stub_template_file(data_tmp_t *,char *, char *, size_t, size_t, struct elf_struct *);