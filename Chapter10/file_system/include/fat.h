#ifndef FAT_H__
#define FAT_H__

#include <stdint.h>

#include "cluster_list.h"
#include "disksim.h"

typedef unsigned char byte;

enum  fat_type {
	FAT_TYPE_FAT12	= 0x01,
	FAT_TYPE_FAT16	= 0x02,
	FAT_TYPE_FAT32	= 0x04,
};

enum fat_limit {
	FAT_LIMIT_MAX_SECTOR_SIZE	= 512,
	FAT_LIMIT_MAX_NAME_LENGTH	= 256,
	FAT_LIMIT_ENTRY_NAME_LENGTH	= 11,	
};

enum fat_eoc {
	FAT_EOC12	= 0x0FF8,
	FAT_EOC16	= 0xFFF8,
	FAT_MS_EOC12	= 0x0FFF,
	FAT_MS_EOC16	= 0xFFFF,

	FAT_EOC32	= 0x0FFFFFF8,
	FAT_MS_EOC32	= 0x0FFFFFFF
};

enum  __attribute__ ((__packed__)) fat_attr {
	FAT_ATTR_READ_ONLY	= 0x01,
	FAT_ATTR_HIDDEN		= 0x02,
	FAT_ATTR_SYSTEM		= 0x04,
	FAT_ATTR_VOLUME_ID	= 0x08,
	FAT_ATTR_DIRECTORY	= 0x10,
	FAT_ATTR_ARCHIVE	= 0x20,
	FAT_ATTR_LONG_NAME	= FAT_ATTR_READ_ONLY | FAT_ATTR_HIDDEN
		                | FAT_ATTR_SYSTEM    | FAT_ATTR_VOLUME_ID,
};

enum fat_dirent_attr {
	FAT_DIRENT_ATTR_FREE		= 0xE5,
	FAT_DIRENT_ATTR_NO_MORE		= 0x00,
	FAT_DIRENT_ATTR_OVERWRITE	= 0x01
};

enum fat_bit_mask16 {
	FAT_BIT_MASK16_SHUT	= 0x8000,
	FAT_BIT_MASK16_ERR	= 0x4000,
};

enum fat_bit_mask32 {
	FAT_BIT_MASK32_SHUT	= 0x08000000,
	FAT_BIT_MASK32_ERR	= 0x04000000
};

#if defined(_WIN32)
	#pragma pack(push, fatstructures)
#elif defined(__linux__)
	#pragma pack(1)
#else
	#error Unknown system!
#endif

struct fat_boot_sector {
	byte		drive_number;
	byte		flags;
	byte		boot_signature;
	uint32_t	volume_id;
	byte		volume_label[11];
	byte		filesystem_type[8];
};

struct fat_bpb {
	byte		jmp_boot[3];
	byte		oem_name[8];

	uint16_t	bytes_per_sector;
	uint8_t		sectors_per_cluster;
	uint16_t	reserved_sector_count;
	uint8_t		number_of_fats;
	uint16_t	root_entry_count;

	uint16_t	total_sectors;

	byte		media;

	uint16_t	fat_size16;
	uint16_t	sectors_per_track;
	uint16_t	number_of_heads;
	uint32_t	total_sectors32;

	union {
		struct fat_boot_sector bs;

		struct {
			uint32_t	fat_size_32;
			uint16_t	exflags;
			uint16_t	filesystem_version;
			uint32_t	root_cluster;
			uint16_t	filesystem_info;
			uint16_t	backup_boot_sectors;
			byte		reserved[12];
			struct fat_boot_sector bs;
		} bpb32;

		byte padding[FAT_LIMIT_MAX_SECTOR_SIZE - 36];
	};
};

struct fat_fsinfo {
	uint32_t lead_signature;
	byte reserved1[480];
	uint32_t struct_signature;
	uint32_t free_count;
	uint32_t next_free;
	byte reserved2[12];
	uint32_t trail_signature;
};

struct fat_dir_entry {
	byte name[FAT_LIMIT_ENTRY_NAME_LENGTH];
	enum fat_attr attribute;	// enum fat_attr is packed, 1-byte
	byte nt_reserved;
	byte created_time_then;
	uint16_t created_time;
	uint16_t created_date;

	uint16_t last_access_date;
	uint16_t first_cluster_hi;

	uint16_t write_time;
	uint16_t write_date;

	uint16_t first_cluster_lo;

	uint32_t filesize;
};

#if defined(_WIN32)
	#pragma pack(pop, fatstructures)
#elif defined(__linux__)
	#pragma pack()
#else
	#error Unknown system!
#endif

struct fat_filesystem {
	enum fat_type	type;
	uint32_t	fat_size;
	enum fat_eoc	eoc_mask;
	struct fat_bpb	bpb;

	struct cluster_list cluster_list;
	struct disk_operations *disk;

	union {
		struct fat_fsinfo info32;

		struct {
			uint32_t free_count;
			uint32_t next_free;
		} info;
	};
};

struct fat_filetime {
	uint16_t year;
};

struct fat_entry_location {
	uint32_t cluster;
	uint32_t sector;
	int32_t number;
};

struct fat_node {
	struct fat_filesystem		*fs;
	struct fat_dir_entry		entry;
	struct fat_entry_location	location;
};

typedef int (*fat_node_add_func)(void *, struct fat_node *);

void fat_unmount(struct fat_filesystem *);

int fat_read_superblock(struct fat_filesystem *, struct fat_node *);
int fat_read_dir(struct fat_node *, fat_node_add_func , void *);

int fat_mkdir(const struct fat_node *, const char *, struct fat_node *);
int fat_rmdir(struct fat_node *);

int fat_lookup(struct fat_node *, const char *, struct fat_node *);
int fat_create(struct fat_node *, const char *, struct fat_node *);

int fat_read(struct fat_node *, unsigned long, unsigned long, char *);
int fat_write(struct fat_node *, unsigned long, unsigned long, const char *);

int fat_remove(struct fat_node *);
int fat_df(struct fat_filesystem *, uint32_t *, uint32_t *);

#endif /* end of #ifndef FAT_H__ */
