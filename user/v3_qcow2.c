#include "v3_qcow2.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>


v3_qcow2_t *v3_qcow2_open(const char *path) {
	if(!path)
		return NULL;
	v3_qcow2_t *res = (v3_qcow2_t*)malloc(sizeof(v3_qcow2_t));
	if(!res)
		goto failed;
	memset(res, 0, sizeof(v3_qcow2_t));
	
	res->fd = open(path, O_RDWR);
	if(res->fd < 0)
		goto clean_mem;

	return res;
clean_mem:
	free(res);
failed:
	return NULL;
}

void v3_qcow2_close(v3_qcow2_t *pf) {
	if(!pf)
		return;

	close(pf->fd);

	free(pf);
}

int v3_qcow2_read(v3_qcow2_t *pf, void *buff, int pos, int len) {
	if(!pf || !buff || !len)
		return 0;
	return 0;
}
