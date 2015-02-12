#ifndef __V3_QCOW2__

#include <stdint.h>
#include <stddef.h>

#define __DEBUG__


#define V3_PACKED __attribute__((packed))
//#define be32_to_cpu	ntohl
//#include <endian.h>
#define QCOW2_MAGIC		(('Q'<<24) | ('F'<<16) | ('I'<<8) | (0xfb))

#define QCOW2_COPIED		(1ULL<<63)
#define QCOW2_COMPRESSED	(1ULL<<62)

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

typedef struct v3_qcow2 {
	int fd;
	struct v3_qcow2 *backing_qcow2;
	char *backing_file_name;
	uint64_t cluster_size;
	uint32_t l1_bits;
	uint64_t l1_mask;
	uint32_t l2_bits;
	uint64_t l2_mask;
	uint32_t refcount_block_bits;
	uint64_t refcount_block_mask;
	uint32_t refcount_table_bits;
	uint64_t refcount_table_mask;
	uint64_t free_cluster_index;
	v3_qcow2_header_t header;
} v3_qcow2_t;


typedef struct v3_qcow2_table_entry {
	uint64_t offset: 62;
	uint8_t compressed: 1;
	uint8_t copied: 1;
} v3_qcow2_table_entry_t;



v3_qcow2_t *v3_qcow2_open(const char *path);

void v3_qcow2_close(v3_qcow2_t *pf);

int v3_qcow2_read(v3_qcow2_t *pf, uint8_t *buff, uint64_t pos, int len);

int v3_qcow2_write(v3_qcow2_t *pf, uint8_t *buff, uint64_t pos, int len);

int v3_addr_split(v3_qcow2_t *qc2, uint64_t addr, uint64_t *l1_idx, uint64_t *l2_idx, uint64_t *offset);

uint64_t v3_qcow2_get_capacity(v3_qcow2_t *pf);


#endif // __V3_QCOW2__
