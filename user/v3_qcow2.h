#ifndef __V3_QCOW2__


#include <stdint.h>

#define V3_PACKED __attribute__((packed))

typedef struct v3_qcow2 {
	int fd;
} v3_qcow2_t;

typedef struct v3_qcow2_header {
	uint32_t magic;
	uint32_t version;

	uint64_t backing_file_offset;
	uint32_t backing_file_size;
	
	uint32_t cluster_bits;
	uint64_t size;

	uint32_t crypt_method;

	uint32_t l1_size;
	uint64_t l1_table_offset;

	uint64_t refcount_table_offset;
	uint32_t refcount_table_clusters;

	uint32_t nb_snapshots;
	uint64_t snapshots_offset;

} V3_PACKED v3_qcow2_header_t;

typedef struct v3_qcow2_snapshot_header {
	uint64_t l1_table_offset;
	uint32_t l1_size;

	uint16_t id_str_size;
	uint16_t name_size;

	uint32_t date_sec;
	uint32_t date_nsec;

	uint64_t vm_clock_nsec;
	uint32_t vm_state_size;
	uint32_t extra_data_size;
} V3_PACKED v3_qcow2_snapshot_header_t;

v3_qcow2_t *v3_qcow2_open(const char *path);

void v3_qcow2_close(v3_qcow2_t *pf);

int v3_qcow2_read(v3_qcow2_t *pf, void *buff, int pos, int len);


#endif // __V3_QCOW2__
