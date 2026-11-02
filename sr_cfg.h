/*
 * sr_cfg.h -- shared layout between the parent (rie_slide, libc, parses the
 * cache + injects this struct into the child) and child_trigger (raw-syscall,
 * pre-dyld). The parent mach_vm_writes one `struct sr_cfg` followed immediately
 * by the slide-info blob bytes into a region it allocates in the child, then
 * hijacks the child's thread to child_trigger with x0 = address of the struct.
 *
 * sr_file_np / sr_mapping MUST be byte-identical to the kernel's
 * shared_file_np (12B) / shared_file_mapping_slide_np (48B).
 */
#ifndef SR_CFG_H
#define SR_CFG_H
#include <stdint.h>

struct sr_file_np {            /* == shared_file_np, 12 bytes */
	int      sf_fd;
	uint32_t sf_mappings_count;
	uint32_t sf_slide;
};

struct sr_mapping {            /* == shared_file_mapping_slide_np, 48 bytes */
	uint64_t sms_address;
	uint64_t sms_size;
	uint64_t sms_file_offset;
	uint64_t sms_slide_size;
	uint64_t sms_slide_start;  /* set by parent to (cfg_child_addr + blob_off) */
	uint32_t sms_max_prot;
	uint32_t sms_init_prot;
};

#define SR_CFG_MAGIC 0x53524347u   /* 'SRCG' */

struct sr_cfg {
	uint32_t magic;
	uint32_t blob_off;             /* page-aligned offset of blob page from cfg start */
	char     main_path[512];       /* files[0] (header) -> child opens, fd patched     */
	char     sub_path[512];        /* files[2] (slide carrier) -> child opens, patched */
	struct sr_file_np files[3];    /* [0]=fd_main, [1]=fd(-1 inject), [2]=fd_sub        */
	struct sr_mapping mappings[3]; /* [0]=header, [1]=fd-1 blob inject, [2]=slide carrier */
	uint64_t fault_addr;           /* slid VA of TARGET_PAGE to fault          */
	uint64_t blob_size;
};

#endif /* SR_CFG_H */
