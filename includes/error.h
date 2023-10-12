#include <stdio.h>

#ifndef _ERROR_H
#define _ERROR_H
#endif

#define MAX_NEW_ERROR_LENGTH 300

#define ALL_GOOD	1
#define OPEN_FAILED 3
#define MMAP_FAILED 5
#define DEV_RAND_FAILED 9
#define RABBIT_FAILED 43
#define NO_SUCH_SECTION 0xdeadbeef
#define OVER_THE_TOP 0xffffffff
#define SPARE_SOME_CHANGE 0x0002c375;

#define BAD_SIZE 99

typedef struct error_t {
	int num;
	char msg[MAX_NEW_ERROR_LENGTH];
} error_t;

#define NEW_ERROR(err_num, str, ...) ({				\
					error_t err; 					\
					err.num = err_num; 				\
					snprintf(err.msg, MAX_NEW_ERROR_LENGTH-1, str, ##__VA_ARGS__); \
					err;							\
				})


#define DIE(str, ...) ({					\
			fprintf(stderr, str, ##__VA_ARGS__);	\
			exit(-1);								\
		})
