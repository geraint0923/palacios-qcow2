#include "v3_qcow2.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static inline uint64_t v3_qcow2_get_cluster_index(v3_qcow2_t *pf, uint64_t file_pos) {
	if(!pf)
		return 0;
	return file_pos >> pf->header.cluster_bits;
}

static int v3_qcow2_get_refcount(v3_qcow2_t *pf, uint64_t file_pos) {
	int res = -1, ret = 0;
	uint16_t val = 0;
	uint64_t idx = 0, table_idx = 0, block_idx = 0, block_offset = 0;
	if(!pf)
		return res;
	idx = v3_qcow2_get_cluster_index(pf, file_pos);
	if(!idx)
		return res;
	block_idx = idx & pf->refcount_block_mask;
	idx >>= pf->refcount_block_bits;
	table_idx = idx & pf->refcount_table_mask;

	lseek(pf->fd, pf->header.refcount_table_offset + table_idx * sizeof(uint64_t), SEEK_SET);
	ret = read(pf->fd, (uint8_t*)&block_offset, sizeof(uint64_t));
	if(ret != sizeof(uint64_t))
		return -1;
	block_offset = be64toh(block_offset);
	lseek(pf->fd, block_offset + block_idx * sizeof(uint16_t), SEEK_SET);
	ret = read(pf->fd, (uint8_t*)&val, sizeof(uint16_t));
	if(ret != sizeof(uint16_t))
		return -1;
	val = be16toh(val);
	
	return val;
}

int v3_qcow2_addr_split(v3_qcow2_t *qc2, uint64_t addr, uint64_t *l1_idx, uint64_t *l2_idx, uint64_t *offset) {
	if(!qc2 || !l1_idx || !l2_idx || !offset) 
		return -1;
	*offset = addr & (qc2->cluster_size - 1);
	addr = addr >> qc2->header.cluster_bits;
	*l2_idx = addr & qc2->l2_mask;
	addr = addr >> qc2->l2_bits;
	*l1_idx = addr * qc2->l1_mask;
	return 0;
}

v3_qcow2_t *v3_qcow2_open(const char *path) {
	int ret = 0;
	if(!path)
		return NULL;
	v3_qcow2_t *res = (v3_qcow2_t*)malloc(sizeof(v3_qcow2_t));
	if(!res)
		goto failed;
	memset(res, 0, sizeof(v3_qcow2_t));
	
	res->fd = open(path, O_RDWR);
	
	if(res->fd < 0)
		goto clean_mem;
	ret = read(res->fd, &res->header, sizeof(res->header));
	if(ret != sizeof(res->header))
		goto clean_mem;
	res->header.magic = be32toh(res->header.magic);
	if(res->header.magic != QCOW2_MAGIC) {
		printf("wrong magic\n");
		goto clean_file;
	} 
#ifdef __DEBUG__
	else {
		printf("right magic\n");
	}
#endif
	res->header.version = be32toh(res->header.version);
	if(res->header.version < 2) {
		printf("wrong version: %d\n", res->header.version);
		goto clean_file;
	}
#ifdef __DEBUG__
	else {
		printf("right version: %d\n", res->header.version);
	}
#endif
	res->header.backing_file_offset = be64toh(res->header.backing_file_offset);
	res->header.backing_file_size = be32toh(res->header.backing_file_size);

	if(res->header.backing_file_size) {
#ifdef __DEBUG__
		printf("backing file size is larger than zero: %d\n", res->header.backing_file_size);
#endif
		res->backing_file_name = (char*)malloc(res->header.backing_file_size + 1);
		if(!res->backing_file_name) {
			printf("failed to allocate memory for backing file name\n");
			goto clean_file;
		}
		res->backing_file_name[res->header.backing_file_size] = 0;
		// FIXME: check the return value of lseek
		ret = lseek(res->fd, res->header.backing_file_offset, SEEK_SET);
		
		ret = read(res->fd, (void*)res->backing_file_name, res->header.backing_file_size);
		if(ret != res->header.backing_file_size) {
			printf("failed to read backing file name from %s\n", path);
			free(res->backing_file_name);
			goto clean_file;
		}
		res->backing_qcow2 = v3_qcow2_open(res->backing_file_name);
		if(res->backing_qcow2) {
			printf("load backing file successfully\n");
		} else {
			printf("failed to load backing file, exit\n");
			exit(0);
		}
#ifdef __DEBUG__
		printf("succeed to read the backing file name: %s\n", res->backing_file_name);
#endif
	} else {
		res->backing_qcow2 = NULL;
#ifdef __DEBUG__
		printf("read no backing file name since size == %d\n", res->header.backing_file_size);
#endif
	}
	res->header.cluster_bits = be32toh(res->header.cluster_bits);
	res->cluster_size = 1 << res->header.cluster_bits;
	res->l2_bits = res->header.cluster_bits - 3;
	res->l2_mask = (((uint64_t)1)<<res->l2_bits) - 1;
	res->l1_bits = sizeof(uint64_t) * 8 - res->l2_bits - res->header.cluster_bits;
	res->l1_mask = (((uint64_t)1)<<res->l1_bits) - 1;
#ifdef __DEBUG__
	printf("cluster_bits: %d\n", res->header.cluster_bits);
#endif
	res->header.size = be64toh(res->header.size);
#ifdef __DEBUG__
	printf("size: %lu\n", res->header.size);
#endif
	res->header.crypt_method = be32toh(res->header.crypt_method);
#ifdef __DEBUG__
	if(res->header.crypt_method) {
		printf("AES cryption\n");
	} else {
		printf("no cryption\n");
	}
#endif

	res->header.l1_size = be32toh(res->header.l1_size);
	res->header.l1_table_offset = be64toh(res->header.l1_table_offset);

	res->header.refcount_table_offset = be64toh(res->header.refcount_table_offset);
	res->header.refcount_table_clusters = be32toh(res->header.refcount_table_clusters);
	
	res->refcount_block_bits = res->header.cluster_bits - 1;
	res->refcount_block_mask = (1LL<<res->refcount_block_bits) - 1;
	res->refcount_table_bits = 8 * sizeof(uint64_t) - res->refcount_block_bits;
	res->refcount_table_mask = (1LL<<res->refcount_table_bits) - 1;

	res->header.nb_snapshots = be32toh(res->header.nb_snapshots);
	res->header.snapshots_offset = be64toh(res->header.snapshots_offset);
#ifdef __DEBUG__
	printf("l1 size: %d\n", res->header.l1_size);
	printf("l1 table offset: %lu\n", res->header.l1_table_offset);

	printf("refcount_table_offset: %lu\n", res->header.refcount_table_offset);
	printf("refcount_table_clusters: %d\n", res->header.refcount_table_clusters);

	printf("nb_snapshots: %d\n", res->header.nb_snapshots);
	printf("snapshots_offset: %lu\n", res->header.snapshots_offset);
#endif


	return res;

clean_file:
	close(res->fd);
clean_mem:
	free(res);
failed:
	return NULL;
}

void v3_qcow2_close(v3_qcow2_t *pf) {
	if(!pf)
		return;

	close(pf->fd);
	if(pf->backing_file_name)
		free(pf->backing_file_name);
	if(pf->backing_qcow2)
		free(pf->backing_qcow2);

	free(pf);
}

static uint64_t v3_qcow2_get_cluster_offset(v3_qcow2_t *qc, uint64_t l1_idx, uint64_t l2_idx, uint64_t offset) {
	uint64_t res = 0;
	uint64_t l1_val = 0, l2_val = 0;
	v3_qcow2_table_entry_t *ent = NULL;
	int ret = 0;
	if(!qc)
		goto done;
	lseek(qc->fd, l1_idx * sizeof(uint64_t) + qc->header.l1_table_offset, SEEK_SET);
	ret = read(qc->fd, (void*)&l1_val, sizeof(uint64_t));
	if(ret != sizeof(uint64_t))
		goto done;
	l1_val = be64toh(l1_val);
	ent = (v3_qcow2_table_entry_t*)&l1_val;
//	l1_val = l1_val & ((((uint64_t)1)<<62)-1);
	if(!ent->offset)
		goto done;
	//lseek(qc->fd, l2_idx * sizeof(uint64_t) + l1_val, SEEK_SET);
	lseek(qc->fd, l2_idx * sizeof(uint64_t) + ent->offset, SEEK_SET);
	ret = read(qc->fd, (void*)&l2_val, sizeof(uint64_t));
	if(ret != sizeof(uint64_t))
		goto done;
	l2_val = be64toh(l2_val);
	ent = (v3_qcow2_table_entry_t*)&l2_val;
//	res = l2_val & ((((uint64_t)1)<<62)-1);
	res = ent->offset;
done:
	return res;
}


static int v3_qcow2_read_cluster(v3_qcow2_t *pf, uint8_t *buff, uint64_t pos, int len) {
	int ret = 0;
	uint64_t l1_idx = 0, l2_idx = 0, offset = 0;
	uint64_t file_offset = 0;
	if(!pf || !buff || !len)
		return -1;
	ret = v3_qcow2_addr_split(pf, pos, &l1_idx, &l2_idx, &offset);
	if(ret)
		return -1;
	file_offset = v3_qcow2_get_cluster_offset(pf, l1_idx, l2_idx, offset);
	if(file_offset) {
		lseek(pf->fd, file_offset + (pos & (pf->cluster_size - 1)), SEEK_SET);
		ret = read(pf->fd, buff, len);
		if(ret != len)
			return -1;
	} else if(pf->backing_qcow2) {
		return v3_qcow2_read(pf->backing_qcow2, buff, pos, len);
	} else {
		memset(buff, 0, len);
	}
	printf("refcount: %d\n", v3_qcow2_get_refcount(pf, file_offset));
	return 0;
}

int v3_qcow2_read(v3_qcow2_t *pf, uint8_t *buff, uint64_t pos, int len) {
	if(!pf || !buff || !len)
		return -1;
	uint64_t next_addr, cur_len;
	int ret = 0;
	while(len) {
		next_addr = (pos + pf->cluster_size) & ~(pf->cluster_size - 1);
		cur_len = next_addr - pos;
		cur_len = cur_len < len ? cur_len : len;
		printf("pos=%lu, len=%lu\n", pos, cur_len);
		ret = v3_qcow2_read_cluster(pf, buff, pos, cur_len);
		if(ret)
			return -1;
		buff += cur_len;
		pos += cur_len;
		len -= cur_len;
	}
	return 0;
}

/*
 * only allocate one cluster
 */
static uint64_t v3_qcow2_alloc_cluster_offset(v3_qcow2_t *pf, uint64_t pos) {
	uint64_t res = 0, l1_idx = 0, l2_idx = 0, offset = 0;
	int ret = 0;
	if(!pf)
		return res;
	
	ret = v3_qcow2_addr_split(pf, pos, &l1_idx, &l2_idx, &offset);
	if(ret)
		return res;
	res = v3_qcow2_get_cluster_offset(pf, l1_idx, l2_idx, offset);
	if(res)
		goto done;
	/*
	 * need to allocate a new cluster for write
	 * also need to update the l1 and l2 table
	 */
done:
	return res;
}


int v3_qcow2_write(v3_qcow2_t *pf, uint8_t *buff, uint64_t pos, int len) {
	if(!pf || !buff || !len) 
		return -1;

	return 0;
}
