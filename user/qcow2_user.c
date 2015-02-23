#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "v3_qcow2.h"

#define MODE_READ 1
#define MODE_WRITE 2

void usage(const char *path) {
	printf("Usage: %s (read|write) file offset len\n", path);
}

int main(int argc, char **argv) {
	int mode = -1;
	if(argc != 5) {
		usage(argv[0]);
		return 0;
	}
	if(strcmp(argv[1], "read") == 0) {
		mode = MODE_READ;
	} else if(strcmp(argv[1], "write") == 0) {
		mode = MODE_WRITE;
	} else {
		printf("unknown mode: %s\n", argv[1]);
		return 0;
	}
	char *path = argv[2];
	uint64_t offset = strtoull(argv[3], NULL, 10);
	uint64_t len = strtoull(argv[4], NULL, 10);
	int i;
	uint8_t *buff = (unsigned char*)malloc(len);
	for(i = 0; i < len; i++) 
		buff[i] = 0;
	if(!buff) {
		printf("failed to malloc of length: %ld\n", len);
		return 0;
	}

	v3_qcow2_t *qcow2 = v3_qcow2_open(path);
	if(!qcow2) {
		printf("failed to open file %s\n", path);
		return -1;
	}
	switch(mode) {
		case MODE_READ:
			v3_qcow2_read(qcow2, (void*)buff, offset, len);
			for(i = 0; i < len; i++) {
				printf("%02x ", buff[i]);
				if(i % 16 == 15)
					printf("\n");
			}
			printf("\n");
			break;
		case MODE_WRITE:
			for(i = 0; i < len; i++) {
				buff[i] = i % 256;
			}
			v3_qcow2_write(qcow2, (void*)buff, offset, len);
			//printf("unsupported currently\n");
			break;
		default:
			printf("error mode: %d\n", mode);
			break;
	}
	v3_qcow2_close(qcow2);
	return 0;
}
