#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void usage(char *path) {
	printf("Usage: %s {output filename} {number of block(1K)}\n", path);
}

int main(int argc, char **argv) {
	if(argc != 3) {
		usage(argv[0]);
		return 0;
	}
	char *path = argv[1];
	int length = atoi(argv[2]), i;
	unsigned int buff[256];
	for(i = 0; i < 256; i++) {
		buff[i] = (i << 24) | (i << 16) | (i << 8) | i;
	}
	int fd = open(path, O_CREAT | O_RDONLY | O_WRONLY, S_IRUSR | S_IRGRP | S_IROTH);
	for(i = 0; i < length; i++) {
		write(fd, buff, sizeof(buff));
	}
	close(fd);
	return 0;
}
