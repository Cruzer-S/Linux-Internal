#include "fat.h"
#include "cluster_list.h"

#include <string.h>	// for the memset()
// -----------------------------------------------------------------------------
// Macro
// -----------------------------------------------------------------------------
#define IS_POINT_ROOT_ENTRY(ENTRY) (						\
	( (ENTRY).attribute & (FAT_ATTR_VOLUME_ID | FAT_ATTR_DIRECTORY) )	\
     &&	( ((ENTRY).first_cluster_lo == 0) || ((ENTRY).name[0] == 32)    )	\
)
// -----------------------------------------------------------------------------
// local function prototype
// -----------------------------------------------------------------------------
static uint32_t get_sector_per_clusterN(uint32_t [][2], uint64_t , uint32_t );
static uint32_t get_sector_per_cluster16(uint64_t , uint32_t );
static uint32_t get_sector_per_cluster32(uint64_t , uint32_t );
static uint32_t get_sector_per_cluster(enum fat_type , uint64_t, uint32_t );

static void fill_fat_size(struct fat_bpb *, enum fat_type );
static int fill_bpb(struct fat_bpb *, enum fat_type , sector , uint32_t );

static enum fat_type get_fat_type(struct fat_bpb *);

static struct fat_entry_location
get_entry_location(const struct fat_dir_entry *);

static int fill_reserved_fat(struct fat_bpb *, byte *);
static int clear_fat(struct disk_operations *, struct fat_bpb *);

static int create_root(struct disk_operations *, struct fat_bpb *);

static int get_fat_sector(struct fat_filesystem *, sector ,
			  sector *, uint32_t *);
static int prepare_fat_sector(struct fat_filesystem *, sector ,
		              sector *, uint32_t *, byte *);

static enum fat_eoc get_fat(struct fat_filesystem *, sector );
static int set_fat(struct fat_filesystem *, sector , uint32_t );
static int fat_format(struct disk_operations *, enum fat_type );
static int validate_bpb(struct fat_bpb *);

static int read_root_sector(struct fat_filesystem *, sector, byte *);
static int write_root_sector(struct fat_filesystem *, sector , const byte *);

static sector calc_physical_sector(struct fat_filesystem *, sector , sector );
static int read_data_sector(struct fat_filesystem *, sector ,
		            sector , byte *);
static int write_data_sector(struct fat_filesystem *, sector , 
		             sector , const byte *);

static int search_free_clusters(struct fat_filesystem *);
static int read_dir_from_sector(struct fat_filesystem *,
		                struct fat_entry_location *,
				byte *, fat_node_add_func , void *);

static enum fat_eoc get_ms_eoc(enum fat_type );
bool is_eoc(enum fat_type , sector );
// -----------------------------------------------------------------------------
// global function
// -----------------------------------------------------------------------------
void fat_unmount(struct fat_filesystem *fs)
{
	cluster_list_release(&fs->cluster_list);
}

int fat_read_superblock(struct fat_filesystem *fs, struct fat_node *root)
{
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];

	if (fs == NULL || fs->disk == NULL)
		return -1;

	if (fs->disk->read_sector(fs->disk, 0, &fs->bpb))
		return -1;

	if (validate_bpb(&fs->bpb))
		return -1;

	fs->type = get_fat_type(&fs->bpb);
	if (fs->type == FAT_TYPE_FAT32)
		return -1;

	if (read_root_sector(fs, 0, sector))
		return -1;

	memset(root, 0x00, sizeof(struct fat_node));
	memcpy(&root->entry, sector, sizeof(struct fat_dir_entry));
	root->fs = fs;

	fs->eoc_mask = get_fat(fs, 1);
	if (fs->type == FAT_TYPE_FAT32) {
		if (fs->eoc_mask & (FAT_BIT_MASK16_SHUT | FAT_BIT_MASK32_ERR))
			return -1;
	} else if (fs->type == FAT_TYPE_FAT16) {
		if (fs->eoc_mask & (FAT_BIT_MASK16_SHUT | FAT_BIT_MASK16_ERR))
			return -1;
	}

	if (fs->bpb.fat_size16 != 0)
		fs->fat_size = fs->bpb.fat_size16;
	else
		fs->fat_size = fs->bpb.bpb32.fat_size_32;

	cluster_list_init(&fs->cluster_list);
	search_free_clusters(fs);

	memset(root->entry.name, 0x20, 11);

	return 0;
}

int fat_read_dir(struct fat_node *dir, fat_node_add_func adder, void *list)
{
	byte data[FAT_LIMIT_MAX_SECTOR_SIZE];
	sector root_entry_count;

	if (IS_POINT_ROOT_ENTRY(dir->entry) && (dir->fs->type == FAT_TYPE_FAT12 || dir->fs->type == FAT_TYPE_FAT16))

	return 0;
}
