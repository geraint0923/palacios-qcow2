/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Yang Yang <geraint0923@gmail.com>
 *	   Weixiao Fu <weixiaofu2014@u.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm.h>
#include <palacios/vmm_dev_mgr.h>

#include <interfaces/vmm_file.h>
#include <palacios/vm_guest.h>

#ifndef V3_CONFIG_DEBUG_QCOWDISK
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif

#define V3_PACKED __attribute__((packed))
//#define be32_to_cpu	ntohl
//#include <endian.h>
#define QCOW2_MAGIC		(('Q'<<24) | ('F'<<16) | ('I'<<8) | (0xfb))

#define QCOW2_COPIED		(1ULL<<63)
#define QCOW2_COMPRESSED	(1ULL<<62)
#define INIT_BUFF_SIZE	(512)
#define printf(...) 

struct disk_state {
    uint64_t capacity; // in bytes

    v3_file_t fd;
};

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
	v3_file_t fd;
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


/*
	just for debug ussage
*/
static uint64_t my_file_write(v3_file_t file, uint8_t *buf, uint64_t len, uint64_t off) {
	PrintDebug(VM_NONE, VCORE_NONE, "MY-QCOW Writing %llu  to %llu\n", len, off);
	return v3_file_write(file, buf, len, off);
}


typedef struct v3_qcow2_table_entry {
	uint64_t offset: 62;
	uint8_t compressed: 1;
	uint8_t copied: 1;
} v3_qcow2_table_entry_t;

static inline uint16_t be16toh(uint16_t v) {
	return ((v&0xff)<<8) | ((v&0xff00)>>8);
}

static inline uint32_t be32toh(uint32_t v) {
	return (((uint32_t)be16toh(v&0x0000ffffU))<<16) | (uint32_t)be16toh((v&0xffff0000U)>>16); 
}

static inline uint64_t be64toh(uint64_t v) {
	return (((uint64_t)be32toh(v&0x00000000ffffffffU))<<32) | (uint64_t)be32toh((v&0xffffffff00000000U)>>32);
}

static inline uint16_t htobe16(uint16_t v) {
	return be16toh(v);
}

static inline uint64_t htobe64(uint64_t v) {
	return be64toh(v);
}

uint64_t v3_qcow2_get_capacity(v3_qcow2_t *pf) {
	return pf ? pf->header.size : 0;
}

static inline uint64_t v3_qcow2_get_cluster_index(v3_qcow2_t *pf, uint64_t file_pos) {
	if(!pf)
		return 0;
	return file_pos >> pf->header.cluster_bits;
}

static int v3_qcow2_get_refcount(v3_qcow2_t *pf, uint64_t idx) {
	int res = -1, ret = 0;
	uint16_t val = 0;
	uint64_t table_idx = 0, block_idx = 0, block_offset = 0;
	if(!pf)
		return res;
	//idx = v3_qcow2_get_cluster_index(pf, file_pos);
	/*
	if(!idx)
		return res;
	*/
	block_idx = idx & pf->refcount_block_mask;
	idx >>= pf->refcount_block_bits;
	table_idx = idx & pf->refcount_table_mask;

	ret = v3_file_read(pf->fd, (uint8_t*)&block_offset, sizeof(uint64_t), pf->header.refcount_table_offset + table_idx * sizeof(uint64_t));
	// FIXME: how to deal with the wrong position
	if(ret != sizeof(uint64_t))
		return 0;
	block_offset = be64toh(block_offset);
	// if cluster is not yet allocated, return 0
	if(!block_offset)
		return 0;
	ret = v3_file_read(pf->fd, (uint8_t*)&val, sizeof(uint16_t), block_offset + block_idx * sizeof(uint16_t));
	// FIXME: how to deal with the wrong position
	if(ret != sizeof(uint16_t))
		return 0;
	val = be16toh(val);
	
	return val;
}
/*
static int v3_qcow2_get_refcount_by_file_position(v3_qcow2_t *pf, uint64_t file_pos) {
	int res = -1;
	uint64_t idx = 0;
	if(!pf)
		return res;
	idx = v3_qcow2_get_cluster_index(pf, file_pos);
	return v3_qcow2_get_refcount(pf, idx);
}
*/
/*
 * to allocate the contiguous clusters
 * return the cluster index in the QCOW2 file
 * return positive if successfully, otherwise zero(0)
 */
static uint64_t v3_qcow2_alloc_clusters(v3_qcow2_t *pf, uint32_t nb_clusters) {
	uint32_t i;
	int refcount = 0;
	uint64_t idx = 0, ret_idx = 0;
	
	if(!nb_clusters)
		return 0;
	if(!pf)
		return 0;
	/*
	 * referenced the algorithm from Qemu
	 */
retry:
	ret_idx = pf->free_cluster_index;
	for(i = 0; i < nb_clusters; i++) {
		idx = pf->free_cluster_index++;
		refcount = v3_qcow2_get_refcount(pf, idx);
		if(refcount < 0) {
			return 0;
		} else if(refcount) {
			goto retry;
		}
	}
	return ret_idx;
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

v3_qcow2_t *v3_qcow2_open(struct v3_vm_info* vm, char *path, int flags) {
	int ret = 0;
	if(!path)
		return NULL;
	v3_qcow2_t *res = (v3_qcow2_t*)V3_Malloc(sizeof(v3_qcow2_t));
	if(!res)
		goto failed;
	memset(res, 0, sizeof(v3_qcow2_t));
	
	res->fd = v3_file_open(vm, path, flags);
	
	if(res->fd < 0)
		goto clean_mem;
	ret = v3_file_read(res->fd, (uint8_t*)&res->header, sizeof(res->header), 0);
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
		res->backing_file_name = (char*)V3_Malloc(res->header.backing_file_size + 1);
		if(!res->backing_file_name) {
			printf("failed to allocate memory for backing file name\n");
			goto clean_file;
		}
		res->backing_file_name[res->header.backing_file_size] = 0;
		// FIXME: check the return value of lseek
		ret = v3_file_read(res->fd, (void*)res->backing_file_name, res->header.backing_file_size, res->header.backing_file_offset);
		if(ret != res->header.backing_file_size) {
			printf("failed to read backing file name from %s\n", path);
			V3_Free(res->backing_file_name);
			goto clean_file;
		}
		res->backing_qcow2 = v3_qcow2_open(vm, res->backing_file_name, flags);
		if(res->backing_qcow2) {
			printf("load backing file successfully\n");
		} else {
			printf("failed to load backing file, exit\n");
			return NULL;
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
	res->free_cluster_index = 1;

	while(1) {
		if(v3_qcow2_get_refcount(res, res->free_cluster_index)) 
			res->free_cluster_index++;
		else 
			break;
	}

	printf("free_cluster_index = %lu\n", res->free_cluster_index);

	/*
	 * TODO: initialize the free cluster index to a reasonable value
	 */

	return res;

clean_file:
	v3_file_close(res->fd);
clean_mem:
	V3_Free(res);
failed:
	return NULL;
}

void v3_qcow2_close(v3_qcow2_t *pf) {
	if(!pf)
		return;

	v3_file_close(pf->fd);
	if(pf->backing_file_name)
		V3_Free(pf->backing_file_name);
	if(pf->backing_qcow2)
		V3_Free(pf->backing_qcow2);

	V3_Free(pf);
}

static uint64_t v3_qcow2_get_cluster_offset(v3_qcow2_t *qc, uint64_t l1_idx, uint64_t l2_idx, uint64_t offset) {
	uint64_t res = 0;
	uint64_t l1_val = 0, l2_val = 0;
	v3_qcow2_table_entry_t *ent = NULL;
	int ret = 0;
	if(!qc)
		goto done;
	if(l1_idx >= qc->header.l1_size) {
		return 0ULL;
	}
	ret = v3_file_read(qc->fd, (void*)&l1_val, sizeof(uint64_t), l1_idx * sizeof(uint64_t) + qc->header.l1_table_offset);
	if(ret != sizeof(uint64_t))
		goto done;
	l1_val = be64toh(l1_val);
	ent = (v3_qcow2_table_entry_t*)&l1_val;
//	l1_val = l1_val & ((((uint64_t)1)<<62)-1);
	if(!ent->offset)
		goto done;
	//lseek(qc->fd, l2_idx * sizeof(uint64_t) + l1_val, SEEK_SET);
	ret = v3_file_read(qc->fd, (void*)&l2_val, sizeof(uint64_t), l2_idx * sizeof(uint64_t) + ent->offset);
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
		ret = v3_file_read(pf->fd, buff, len, file_offset + (pos & (pf->cluster_size - 1)));
		// it is possible to get a negative value because of the hole
//		if(ret != len)
		if(ret < 0)
			return -1;
	} else if(pf->backing_qcow2) {
		return v3_qcow2_read_cluster(pf->backing_qcow2, buff, pos, len);
	} else {
		memset(buff, 0, len);
	}
	printf("refcount: %d\n", v3_qcow2_get_refcount_by_file_position(pf, file_offset));
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

// in this function, we assmue we must have the corresponding refcount block
// so we will not allocate the refcount block here
static int v3_qcow2_update_refcount(v3_qcow2_t *pf, uint64_t cluster_idx, int count) {
	uint64_t table_idx = 0, block_idx = 0, block_offset = 0, idx = cluster_idx;
	int ret = 0;
	uint16_t val = count;
	if(!pf)
		return -1;
	
	block_idx = idx & pf->refcount_block_mask;
	idx >>= pf->refcount_block_bits;
	table_idx = idx & pf->refcount_table_mask;
	ret = v3_file_read(pf->fd, (uint8_t*)&block_offset, sizeof(uint64_t), pf->header.refcount_table_offset + table_idx * sizeof(uint64_t));
	if(ret != sizeof(uint64_t) || !block_offset) {
		printf("something wrong with update refcount, exit\n");
		return -1;
	}
	block_offset = be64toh(block_offset);
	val = htobe16(val);
	ret = v3_file_write(pf->fd, (uint8_t*)&val, sizeof(uint16_t), block_offset + block_idx * sizeof(uint16_t));
	if(ret != sizeof(uint16_t)) {
		printf("write failed when update refcount, exit\n");
		return -1;
	}
	return 0;
}

// in this function, we need to resolve the circular dependency when the refcount itself is not allocated
// since for cluster_bits==16, it needs 65536G to use more than one clusters to contain all the refcount 
// table, we don't handle that case
// of course, we can handle this case if we have enough time
static int v3_qcow2_alloc_refcount(v3_qcow2_t *pf, uint64_t cluster_idx) {
	int res = -1, ret;
	uint8_t zero_buff[INIT_BUFF_SIZE];
	uint16_t val = 0;
	uint64_t idx = cluster_idx, table_idx = 0, block_idx = 0, block_offset = 0;
	uint64_t new_cluster_idx, new_table_idx = 0, new_block_idx = 0, write_value;
//	int i;
	uint64_t left_size, start_offset, buf_length;
	if(!pf)
		return -1;
	block_idx = idx & pf->refcount_block_mask;
	idx >>= pf->refcount_block_bits;
	table_idx = idx & pf->refcount_table_mask;

	// TODO: re-allocate larger refcount table if needed

retry:
	ret = v3_file_read(pf->fd, (uint8_t*)&block_offset, sizeof(uint64_t), pf->header.refcount_table_offset + table_idx * sizeof(uint64_t));
	if(ret != sizeof(uint64_t) || table_idx > pf->header.refcount_table_clusters) {
		printf("read failed, exit!\n");
		return -1;	
	}
	block_offset = be64toh(block_offset);
	if(!block_offset) {
		// allocate a cluster as a new refcount block
		// and also we need to initialize this cluster with zeros
		new_cluster_idx = v3_qcow2_alloc_clusters(pf, 1);
		if(new_cluster_idx <= 0) {
			printf("failed to allocate new cluster, exit!\n");
			return -1;
		}
		idx = new_cluster_idx;
		new_block_idx = idx & pf->refcount_block_mask;
		idx >>= pf->refcount_block_bits;
		new_table_idx = idx & pf->refcount_table_mask;
		// initialize with zeros
		start_offset = new_cluster_idx << pf->header.cluster_bits;
		left_size = pf->cluster_size;
		memset(zero_buff, 0, INIT_BUFF_SIZE);
		while(left_size > 0) {
			//ret = write(pf->fd, zero_buff, INIT_BUFF_SIZE < left_size ? INIT_BUFF_SIZE : left_size);
			buf_length = INIT_BUFF_SIZE < left_size ? INIT_BUFF_SIZE : left_size;
			ret = my_file_write(pf->fd, zero_buff, buf_length, start_offset);
			start_offset += buf_length;
			if(ret <= 0) {
				printf("something wrong with write, exit\n");
				return -1;
			}
			left_size -= INIT_BUFF_SIZE;
		}
		// update the refcount table with the new refcount block
		write_value = htobe64(new_table_idx << pf->header.cluster_bits);
		ret = my_file_write(pf->fd, (uint8_t*)&write_value, sizeof(uint64_t), pf->header.refcount_table_offset + table_idx * sizeof(uint64_t));
		if(new_table_idx == table_idx) {
			// in the same refcount block, increase its refcount here
			val = htobe16(1);
			ret = my_file_write(pf->fd, (uint8_t*)&val, sizeof(uint16_t), (new_table_idx << pf->header.cluster_bits) + sizeof(uint16_t) * new_block_idx);
		} else {
			v3_qcow2_alloc_refcount(pf, new_cluster_idx);
			v3_qcow2_update_refcount(pf, new_cluster_idx, 1);
		}

		goto retry;
	}
	/*
	lseek(pf->fd, block_offset + block_idx * sizeof(uint16_t), SEEK_SET);
	ret = read(pf->fd, (uint8_t*)&val, sizeof(uint16_t));
	if(ret != sizeof(uint16_t)) {
		printf("another read failed, exit!\n");
		exit(-1);
	}
	*/
	res = 0;
	return res;
}



static int v3_qcow2_increase_refcount(v3_qcow2_t *pf, uint64_t cluster_idx) {
	int refcount = 0;
	if(!pf)
		return -1;
	refcount = v3_qcow2_get_refcount(pf, cluster_idx);
	printf("***increase!!\n");
	if(refcount <= 0) {
		// execute to here means that no cluster block entry is allocated
		// we need to allocate the entry here
		refcount = v3_qcow2_alloc_refcount(pf, cluster_idx);
		if(refcount) {
			printf("something wrong when allocate refcount entry, exit!\n");
			return -1;
		}
		refcount = 1;	
	} else {
		refcount++;
	}
	// write the refcount back to the file
	return v3_qcow2_update_refcount(pf, cluster_idx, refcount);
}
/*
static int v3_qcow2_decrease_refcount(v3_qcow2_t *pf, uint64_t cluster_idx) {
	int refcount = 0;
	if(!pf)
		return -1;
	refcount = v3_qcow2_get_refcount(pf, cluster_idx);
	if(refcount <= 0) {
		printf("decrease the refcount for a cluster, exit\n");
		return -1;
	}
	refcount--;
	return v3_qcow2_update_refcount(pf, cluster_idx, refcount);
}

*/

/*
 * do nothing but return if no need to allocate new cluster
 * only allocate one cluster if necessary
 */
static uint64_t v3_qcow2_alloc_cluster_offset(v3_qcow2_t *pf, uint64_t pos) {
	uint64_t res = 0, l1_idx = 0, l2_idx = 0, offset = 0, l2_cluster_offset, done_bytes;
	uint64_t l2_cluster_idx;
	uint64_t cluster_offset = 0;
	int ret = 0;
	uint8_t init_buff[INIT_BUFF_SIZE], *data_buff;
	if(!pf)
		return res;
	
	ret = v3_qcow2_addr_split(pf, pos, &l1_idx, &l2_idx, &offset);
	if(ret)
		return res;
	// FIXME: in fact, we should check the refcount to be 1,
	// otherwise we should copy
	// do it later
	res = v3_qcow2_get_cluster_offset(pf, l1_idx, l2_idx, offset);
	if(res) {
		cluster_offset = res;
		goto done;
	}

	/*
	 * need to allocate a new cluster for write
	 * also need to update the l1 and l2 table
	 */
	ret = v3_file_read(pf->fd, (uint8_t*)&l2_cluster_offset, sizeof(uint64_t),  pf->header.l1_table_offset + sizeof(uint64_t) * l1_idx);
	l2_cluster_offset = be64toh(l2_cluster_offset) & ~(QCOW2_COPIED | QCOW2_COMPRESSED);
	if(!l2_cluster_offset/*l1_idx >= pf->header.l1_size*/) {
		/*
		 * need to allocate a new l1 entry
		 * for simplicity, only allow 2^(cluster_bits-3) entry in l1 table
		 */
		l2_cluster_idx = v3_qcow2_alloc_clusters(pf, 1);
		l2_cluster_offset = (l2_cluster_idx << pf->header.cluster_bits);
		// increase the reference count for this cluster
		v3_qcow2_increase_refcount(pf, l2_cluster_idx);
		memset(init_buff, 0, INIT_BUFF_SIZE);
		for(done_bytes = 0; done_bytes < pf->cluster_size; done_bytes += INIT_BUFF_SIZE) {
			ret = my_file_write(pf->fd, init_buff, INIT_BUFF_SIZE, l2_cluster_offset + done_bytes);
		}
		/*
		 * set all the slot in gap to zero
		 * not necessary since the l1_size must be larger than allowed size
		 */
		/*
		lseek(pf->fd, pf->header.l1_table_offset + sizeof(uint64_t) * pf->header.l1_size, SEEK_SET);
		while(l1_idx > pf->header.l1_size) {
			ret = write(pf->fd, (uint8_t*)&zero_tmp, sizeof(uint64_t));
			pf->header.l1_size++;
		}
		*/
		/*
		 * set the copied bit
		 */
		l2_cluster_offset |= QCOW2_COPIED;
		l2_cluster_offset = htobe64(l2_cluster_offset);
		ret = my_file_write(pf->fd, (uint8_t*)&l2_cluster_offset, sizeof(uint64_t),  pf->header.l1_table_offset + sizeof(uint64_t) * l1_idx);
		/*
		 * update the header and write the update to file
		 * not necessary either
		 */
		/*
		pf->header.l1_size = l1_idx + 1;
		l2_cluster_offset = htobe64(pf->header.l1_size);
		lseek(pf->fd, offsetof(v3_qcow2_header_t, l1_size), SEEK_SET);
		ret = write(pf->fd, &l2_cluster_offset, sizeof(uint64_t));
		*/
		// DONE: TODO: increase the refcount of this newly allocated cluster
		// need to do it later
	} else {
		/*
		 * something wrong
		 */
		/*
		printf("%s: %d => impossible branch", __FILE__, __LINE__);
		return -1;
		*/
	}
	ret = v3_file_read(pf->fd, (uint8_t*)&l2_cluster_offset, sizeof(uint64_t),  pf->header.l1_table_offset + sizeof(uint64_t) * l1_idx);
	l2_cluster_offset = be64toh(l2_cluster_offset) & ~(QCOW2_COPIED | QCOW2_COMPRESSED);
	/*
	 * begin to retrieve cluster_offset
	 */
	// adjust the l2_cluster_offset to the right entry address
	l2_cluster_offset += sizeof(uint64_t) * l2_idx;
	ret = v3_file_read(pf->fd, (uint8_t*)&cluster_offset, sizeof(uint64_t), l2_cluster_offset);
	cluster_offset = be64toh(cluster_offset) & ~(QCOW2_COPIED | QCOW2_COMPRESSED);
	if(!cluster_offset) {
		/*
		 * if the cluster_offset is not allocated
		 */
		l2_cluster_idx = v3_qcow2_alloc_clusters(pf, 1);
		cluster_offset = (l2_cluster_idx << pf->header.cluster_bits);
		// TODO: initialization
		// initialize the cluster with the original data
		data_buff = (uint8_t*)V3_Malloc(pf->cluster_size);
		if(data_buff) {
			pos = (pos >> pf->header.cluster_bits) << pf->header.cluster_bits;
			v3_qcow2_read_cluster(pf, data_buff, pos, pf->cluster_size);
			ret = my_file_write(pf->fd, data_buff, pf->cluster_size, cluster_offset);
			V3_Free(data_buff);
		} else {
			printf("failed to initialize the original data\n");
		}
		offset = htobe64(cluster_offset | QCOW2_COPIED);
		ret = my_file_write(pf->fd, (uint8_t*)&offset, sizeof(uint64_t), l2_cluster_offset);
		// TODO: increase refcount of the new-allocated cluster
		v3_qcow2_increase_refcount(pf, l2_cluster_idx);
	}

done:
	return cluster_offset;
}

int v3_qcow2_write_cluster(v3_qcow2_t *pf, uint8_t *buff, uint64_t pos, int len) {
	if(!pf || !buff)
		return -1;
	uint64_t cluster_addr, cluster_offset;
	int ret = 0;
	cluster_addr = v3_qcow2_alloc_cluster_offset(pf, pos);
	if(!cluster_addr) {
		printf("zero cluster address\n");
		return -1;
	}
	cluster_offset = pos & (pf->cluster_size - 1);
	ret = my_file_write(pf->fd, buff, len, cluster_addr + cluster_offset);
	if(ret != len) {
		printf("ret != len\n");
		return -1;
	}
	return 0;
}

int v3_qcow2_write(v3_qcow2_t *pf, uint8_t *buff, uint64_t pos, int len) {
	if(!pf || !buff || !len) 
		return -1;
	uint64_t next_addr, cur_len;
	int ret = 0;
	while(len) {
		next_addr = (pos + pf->cluster_size) & ~(pf->cluster_size - 1);
		cur_len = next_addr - pos;
		cur_len = cur_len < len ? cur_len : len;
		printf("pos=%lu, len=%lu\n", pos, cur_len);
		ret = v3_qcow2_write_cluster(pf, buff, pos, cur_len);
		if(ret)
			return -1;
		buff += cur_len;
		pos += cur_len;
		len -= cur_len;
	}
	return ret;
}

static int read(uint8_t * buf, uint64_t lba, uint64_t num_bytes, void * private_data) {
    v3_qcow2_t * disk = (v3_qcow2_t *) private_data;
    PrintDebug(VM_NONE, VCORE_NONE, "QCOW Reading %llu bytes from %llu to 0x%p\n", num_bytes, lba, buf);

    if (lba + num_bytes > disk->header.size) {
	PrintError(VM_NONE, VCORE_NONE, "Out of bounds read: lba=%llu, num_bytes=%llu, capacity=%llu\n",
		   lba, num_bytes, disk->header.size);
	return -1;
    }

    return v3_qcow2_read(disk, buf, lba, num_bytes);
}


static int write(uint8_t * buf, uint64_t lba, uint64_t num_bytes, void * private_data) {
    v3_qcow2_t * disk = (v3_qcow2_t *) private_data;

    PrintDebug(VM_NONE, VCORE_NONE, "QCOW Writing %llu bytes from 0x%p to %llu\n", num_bytes,  buf, lba);

    if (lba + num_bytes > disk->header.size) {
	PrintError(VM_NONE, VCORE_NONE, "Out of bounds read: lba=%llu, num_bytes=%llu, capacity=%llu\n",
		   lba, num_bytes, disk->header.size);
	return -1;
    }

    return v3_qcow2_write(disk, buf, lba, num_bytes);

}


static uint64_t get_capacity(void * private_data) {
    v3_qcow2_t * disk = (v3_qcow2_t *)private_data;

    PrintDebug(VM_NONE, VCORE_NONE, "Querying QCOWDISK capacity %llu\n", v3_qcow2_get_capacity(disk));
    return v3_qcow2_get_capacity(disk);

}

static struct v3_dev_blk_ops blk_ops = {
    .read = read, 
    .write = write,
    .get_capacity = get_capacity,
};




static int disk_free(struct disk_state * disk) {
    v3_file_close(disk->fd);
    
    V3_Free(disk);
    return 0;
}

static struct v3_device_ops dev_ops = {
    .free = (int (*)(void *))disk_free,
};




static int disk_init(struct v3_vm_info * vm, v3_cfg_tree_t * cfg) {
    v3_qcow2_t * disk = NULL;
    char * path = v3_cfg_val(cfg, "path");
    char * dev_id = v3_cfg_val(cfg, "ID");
    char * writable = v3_cfg_val(cfg, "writable");
    char * writeable = v3_cfg_val(cfg, "writeable");

    v3_cfg_tree_t * frontend_cfg = v3_cfg_subtree(cfg, "frontend");
    int flags = FILE_OPEN_MODE_READ;

    V3_Print(vm,VCORE_NONE,"Welcome to the QCOWDISK Implementation!\n");

    if ( ((writable) && (writable[0] == '1')) ||
	 ((writeable) && (writeable[0] == '1')) ) {
	flags |= FILE_OPEN_MODE_WRITE;
    }

    if (path == NULL) {
	PrintError(vm, VCORE_NONE, "Missing path (%s) for %s\n", path, dev_id);
	return -1;
    }




    disk = v3_qcow2_open(vm, path, flags);

    if (disk == NULL) {
	PrintError(vm, VCORE_NONE, "Could not open file disk:%s\n", path);
	return -1;
    }

    struct vm_device * dev = v3_add_device(vm, dev_id, &dev_ops, disk);

    if (dev == NULL) {
	PrintError(vm, VCORE_NONE, "Could not attach device %s\n", dev_id);
	V3_Free(disk);
	return -1;
    }


    if (v3_dev_connect_blk(vm, v3_cfg_val(frontend_cfg, "tag"), 
			   &blk_ops, frontend_cfg, disk) == -1) {
	PrintError(vm, VCORE_NONE, "Could not connect %s to frontend %s\n", 
		   dev_id, v3_cfg_val(frontend_cfg, "tag"));
	v3_remove_device(dev);
	return -1;
    }
    

    return 0;
}


device_register("QCOWDISK", disk_init)
