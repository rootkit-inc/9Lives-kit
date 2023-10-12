#ifndef _HEXDUMP_H
#define _HEXDUMP_H
#endif

void hexdump(char *data, size_t len) {
	int i;
	int minus;
	fprintf(stdout, "====~==== [ HEXDUMP BEGIN] ====~====\n");
	for (i = 0; i < len; i++) {
		if (i == len-1)
			printf("%02x ", (unsigned char)(*(data+i)));

		if ((i % 16 == 0 && i != 0) || i == len-1) {
			if (i == len-1)
				for (int l = 0; l < 16 - (i % 16); l++)
					printf("   ");

			printf("\t|\t");
			minus = 16;
			if (i == len-1) {
				minus -= (16-(i % 16));
			}

			for (int j = i-minus; j < i+((i == len-1) ? 1 : 0); j++){
				char chr = (unsigned char)(*(data+j));
				if (chr == ' ' || chr == '\n' || chr == '\r') {
					putchar('.');
				} else {
					putchar(chr);
				}
			}
			if (i == len-1) goto end;
			if (i % 16 == 0) {
				printf("\n");
			}

			// if (i == 16) {
			// 	printf("%02x ", (unsigned char)(*(data+i)));
			// 	i++;
			// }
		}
		printf("%02x ", (unsigned char)(*(data+i)));
	}
	end: printf("\n====~==~= [ HEXDUMP END ] =~==~====\n");
}