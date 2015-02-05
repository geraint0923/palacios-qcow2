#include "v3_qcow2.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>


v3_qcow2_t *qcow2_open(const char *path) {
	if(!path)
		return NULL;
}

void qcow2_close(v3_qcow2_t *pf) {
	if(!pf)
		return;
}

int qcow2_read(v3_qcow2_t *pf, void *buff, int pos, int len) {
	if(!pf || !buff || !len)
		return 0;
	return 0;
}
