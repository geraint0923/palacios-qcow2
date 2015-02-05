#ifndef __V3_QCOW2__



typedef struct v3_qcow2 {
	int fd;
} v3_qcow2_t;

v3_qcow2_t *qcow2_open(const char *path);

void qcow2_close(v3_qcow2_t *pf);

int qcow2_read(v3_qcow2_t *pf, void *buff, int pos, int len);


#endif // __V3_QCOW2__
