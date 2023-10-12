// #include <elf.h>

// #ifndef _ROXY_ELF_H
// #define _ROXY_ELF_H
// #endif

// #ifndef _ELF_HELPER
// #include "../elf.h"
// #endif

// typedef struct dactyl_frame_t {
// 	struct meta {
// 		char *orig_name;
// 		char *fake_name;
// 		char key[16];
// 		size_t offset;
// 		size_t size;
// 	} meta;
// 	char 	*memmap;
// 	char 	*ecrypt_memmap;
// } dactyl_frame_t;


// typedef struct dactyl_t {
// 	dactyl_frame_t *frame;
// } dactyl_t;

// struct error_t encrypt(struct elf_struct *, char *, size_t);
// int ecrypt_symbol(dactyl_t *, int, Elf_Sym, unsigned char *, unsigned char *);