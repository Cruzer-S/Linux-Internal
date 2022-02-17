#include "fat.h"

#include <string.h>	// for the memset()

#include "cluster_list.h"
// -----------------------------------------------------------------------------
// Macro
// -----------------------------------------------------------------------------
#define IS_POINT_ROOT_ENTRY(ENTRY) (						\
	( (ENTRY).attribute & (FAT_ATTR_VOLUME_ID | FAT_ATTR_DIRECTORY) )	\
     &&	( ((ENTRY).first_cluster_lo == 0) || ((ENTRY).name[0] == 32)    )	\
)

#define GET_FIRST_CLUSTER(ENTRY)	(					\
		(	(((uint32_t) (ENTRY).first_cluster_hi) << 16)		\
		      | ((ENTRY).first_cluster_lo)			)	\
	)

#define SET_FIRST_CLUSTER(ENTRY, CLUSTER) do {					\
	(ENTRY).first_cluster_hi << 16;						\
	(ENTRY).first_cluster_lo = (uint16_t) ((CLUSTER) & 0xFFFF);		\
} while (false)

#define MIN(A, B) ( (A) < (B) ? (A) : (B) )
#define MAX(A, B) ( (A) > (B) ? (A) : (B) )
// -----------------------------------------------------------------------------
// local function prototype
// -----------------------------------------------------------------------------
static uint32_t get_sector_per_clusterN(uint32_t [][2], uint64_t , uint32_t );
static uint32_t get_sector_per_cluster16(uint64_t , uint32_t );
static uint32_t get_sector_per_cluster32(uint64_t , uint32_t );
static uint32_t get_sector_per_cluster(enum fat_type , uint64_t, uint32_t );

static void fill_fat_size(struct fat_bpb *, enum fat_type );
static int fill_bpb(struct fat_bpb *, enum fat_type , sector_t , uint32_t );

static enum fat_type get_fat_type(struct fat_bpb *);

static struct fat_entry_location get_entry_location(
		const struct fat_dir_entry *
);

static int fill_reserved_fat(struct fat_bpb *, byte *);
static int clear_fat(struct disk_operations *, struct fat_bpb *);

static int create_root(struct disk_operations *, struct fat_bpb *);

static int get_fat_sector(
		struct fat_filesystem *, sector_t , sector_t *, uint32_t *
);
static int prepare_fat_sector(
		struct fat_filesystem *, sector_t ,
		sector_t *, uint32_t *, byte *
);

static enum fat_eoc get_fat(struct fat_filesystem *, sector_t );
static int set_fat(struct fat_filesystem *, sector_t , uint32_t );
static int fat_format(struct disk_operations *, enum fat_type );
static int validate_bpb(struct fat_bpb *);

static int read_root_sector(struct fat_filesystem *, sector_t , byte *);
static int write_root_sector(struct fat_filesystem *, sector_t , const byte *);

static sector_t calc_physical_sector(
		struct fat_filesystem *, sector_t , sector_t 
);
static int read_data_sector(
		struct fat_filesystem *, sector_t , sector_t , byte *
);
static int write_data_sector(
		struct fat_filesystem *, sector_t , sector_t , const byte *
);

static int search_free_clusters(struct fat_filesystem *);
static int read_dir_from_sector(
		struct fat_filesystem *, struct fat_entry_location *,
		byte *, fat_node_add_func , void *
);

static enum fat_eoc get_ms_eoc(enum fat_type );
static bool is_eoc(enum fat_type , sector_t );
static int add_free_cluster(struct fat_filesystem *, sector_t );
static sector_t alloc_free_cluster(struct fat_filesystem * );
static sector_t span_clustser_chain(struct fat_filesystem *, sector_t );
static int find_entry_at_sector(
		const byte *, const byte *, uint32_t , uint32_t 
);
static int find_entry_on_root(
		struct fat_filesystem *, const struct fat_entry_location *,
		const byte *, struct fat_node *
);
static int find_entry_on_data(
		struct fat_filesystem *, const struct fat_entry_location *,
		const byte, struct fat_node *
);
static int lookup_entry(
		struct fat_filesystem *, const struct fat_entry_location *,
		const char *, struct fat_node *
);
static int set_entry(
		struct fat_filesystem *, const struct fat_entry_location *,
		const struct fat_dir_entry *
);
static int insert_entry(
		const struct fat_node *, struct fat_node *,
		enum fat_dirent_attr 
);
static void upper_string(char *, int );
static int format_name(struct fat_filesystem *, char *);
static int free_cluster_chain(struct fat_filesystem *, uint32_t );
static int has_sub_entries(
		struct fat_filesystem *, const struct fat_dir_entry *
);

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
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	sector_t root_entry_count;
	struct fat_entry_location location;

	if ((IS_POINT_ROOT_ENTRY(dir->entry))
	&&  (dir->fs->type == (FAT_TYPE_FAT12 | FAT_TYPE_FAT16)))
	{
		if (dir->fs->type == FAT_TYPE_FAT32)
			return -1;

		root_entry_count = dir->fs->bpb.root_entry_count;
		for (int i = 0; i < root_entry_count; i++) {
			read_root_sector(dir->fs, i, sector);
			location.cluster = 0;
			location.sector = i;
			location.number = 0;

			if (read_dir_from_sector(
				dir->fs, &location, sector, adder, list
			))
				break;
		}
	} else {
		int i = GET_FIRST_CLUSTER(dir->entry);
		do {
			for (int j = 0;
			     j < dir->fs->bpb.sectors_per_cluster;
			     j++)
			{
				read_data_sector(dir->fs, i, j, sector);
				location.cluster = i;
				location.sector = j;
				location.number = 0;

				if (read_dir_from_sector(
					dir->fs, &location, sector, adder, list
				))
					break;
			}
		} while ( (!is_eoc(dir->fs->type, i)) && (i != 0) );
	}

	return 0;
}

int fat_mkdir(
		const struct fat_node *parent, const char *entry_name,
		struct fat_node *ret
){
	struct fat_node dot_node, dotdot_node;
	uint32_t first_cluster;
	char name[FAT_LIMIT_MAX_NAME_LENGTH];
	int result;

	strncpy(name, entry_name, FAT_LIMIT_MAX_NAME_LENGTH);

	if (format_name(parent->fs, name))
		return -1;

	memset(ret, 0x00, sizeof(struct fat_node));
	memcpy(ret->entry.name, name, FAT_LIMIT_MAX_NAME_LENGTH);
	ret->entry.attribute = FAT_ATTR_DIRECTORY;
	first_cluster = alloc_free_cluster(parent->fs);

	if (first_cluster == 0)
		return -1;

	set_fat(parent->fs, first_cluster, get_ms_eoc(parent->fs->type));

	SET_FIRST_CLUSTER(ret->entry, first_cluster);
	result = insert_entry(parent, ret, FAT_DIRENT_ATTR_NO_MORE);
	if (result)
		return -1;

	ret->fs = parent->fs;

	memset(&dot_node, 0x00, sizeof(struct fat_node));
	memset(dot_node.entry.name, 0x20, FAT_LIMIT_ENTRY_NAME_LENGTH);
	dot_node.entry.name[0] = '.';
	dot_node.entry.attribute = FAT_ATTR_DIRECTORY;
	insert_entry(ret, &dot_node, FAT_DIRENT_ATTR_OVERWRITE);

	memset(&dotdot_node, 0x00, sizeof(struct fat_node));
	memset(dotdot_node.entry.name, 0x20, 11);
	dotdot_node.entry.name[0] = '.';
	dotdot_node.entry.name[1] = '.';
	dotdot_node.entry.attribute = FAT_ATTR_DIRECTORY;

	SET_FIRST_CLUSTER(dotdot_node.entry, GET_FIRST_CLUSTER(parent->entry)); 
	insert_entry(ret, &dotdot_node, FAT_DIRENT_ATTR_NO_MORE); 

	return 0;
}

int fat_rmdir(struct fat_node *dir)
{
	if (has_sub_entries(dir->fs, &dir->entry))
		return -1;

	if ( !(dir->entry.attribute & FAT_ATTR_DIRECTORY) )
		return -1;

	dir->entry.name[0] = FAT_DIRENT_ATTR_FREE;
	set_entry(dir->fs, &dir->location, &dir->entry);
	free_cluster_chain(dir->fs, GET_FIRST_CLUSTER(dir->entry));

	return 0;
}

int fat_lookup(
		struct fat_node *parent, const char *entry_name,
		struct fat_node *ret_entry
){
	struct fat_entry_location begin;
	char formatted_name[FAT_LIMIT_ENTRY_NAME_LENGTH] = { 0, };

	begin.cluster = GET_FIRST_CLUSTER(parent->entry);
	begin.sector = 0;
	begin.number = 0;

	strncpy(formatted_name, entry_name, FAT_LIMIT_ENTRY_NAME_LENGTH);

	if (format_name(parent->fs, formatted_name))
		return -1;

	if (IS_POINT_ROOT_ENTRY(parent->entry))
		begin.cluster = 0;

	return 0;
}

int fat_create(
		struct fat_node *parent, const char *entry_name,
		struct fat_node *ret_entry
){
	struct fat_entry_location first;
	char name[FAT_LIMIT_ENTRY_NAME_LENGTH] = { 0, };

	strncpy(name, entry_name, FAT_LIMIT_ENTRY_NAME_LENGTH);
	if (format_name(parent->fs, name))
		return -1;

	memset(ret_entry, 0x00, sizeof(struct fat_node));
	memcpy(ret_entry->entry.name, name, FAT_LIMIT_ENTRY_NAME_LENGTH);

	first.cluster = parent->entry.first_cluster_lo;
	first.sector = 0;
	first.number = 0;

	if (lookup_entry(parent->fs, &first, name, ret_entry) == 0)
		return -1;

	ret_entry->fs = parent->fs;
	if (insert_entry(parent, ret_entry, 0))
		return -1;

	return 0;
}

int fat_read(
		struct fat_node *file, unsigned long offset,
		unsigned long length, char *buffer
){
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	uint32_t current_offset, current_cluster, cluster_seq = 0;
	uint32_t cluster_number, sector_number, sector_offset;
	uint32_t read_end;
	uint32_t cluster_size, cluster_offset = 0;

	current_cluster = GET_FIRST_CLUSTER(file->entry);
	read_end = MIN(offset + length, file->entry.filesize);

	current_offset = offset;

	cluster_size = file->fs->bpb.bytes_per_sector
		     * file->fs->bpb.sectors_per_cluster;
	cluster_offset = cluster_size;

	while (offset > cluster_offset)
	{
		current_cluster = get_fat(file->fs, current_cluster);
		cluster_offset += cluster_size;

		cluster_seq++;
	}

	while (current_offset < read_end)
	{
		uint32_t copy_length;

		cluster_number = current_offset / cluster_size;
		if (cluster_seq != cluster_number) {
			cluster_seq++;
			current_cluster = get_fat(file->fs, current_cluster);
		}

		sector_number = (
			current_offset / (file->fs->bpb.bytes_per_sector)
		) % file->fs->bpb.sectors_per_cluster;

		sector_offset = current_offset % file->fs->bpb.bytes_per_sector;

		if (read_data_sector(
			file->fs, current_cluster, sector_number, sector
		    ))
			break;

		copy_length = MIN(
			file->fs->bpb.bytes_per_sector - sector_offset,
			read_end - current_offset
		);

		memcpy(buffer, &sector[sector_offset], copy_length);

		buffer += copy_length;
		current_offset += copy_length;
	}

	return current_offset - offset;
}

int fat_write(
		struct fat_node *file, unsigned long offset,
		unsigned long length, const char *buffer
){
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	uint32_t current_offset, current_cluster, cluster_seq = 0;
	uint32_t cluster_number, sector_number, sector_offset;

	uint32_t read_end, cluster_size;

	current_cluster = GET_FIRST_CLUSTER(file->entry);
	read_end = offset + length;

	current_offset = offset;

	cluster_size = file->fs->bpb.bytes_per_sector 
		     * file->fs->bpb.sectors_per_cluster;

	while (offset > cluster_size) {
		current_cluster = get_fat(file->fs, current_cluster);
		cluster_size += cluster_size;
		cluster_seq ++;
	}

	while (current_offset < read_end) {
		uint32_t copy_length;

		cluster_number = current_offset / cluster_size;
		if (current_cluster == 0) {
			current_cluster = alloc_free_cluster(file->fs);
			if (current_cluster == 0)
				return -1;
			SET_FIRST_CLUSTER(file->entry, current_cluster);
			set_fat(file->fs, current_cluster,
			        get_ms_eoc(file->fs->type));
		}

		if (cluster_seq != cluster_number) {
			uint32_t next_cluster;
			cluster_seq++;

			next_cluster = get_fat(file->fs, current_cluster);
			if (is_eoc(file->fs->type, next_cluster)) {
				next_cluster = span_clustser_chain(
					file->fs, current_cluster
				);

				if (next_cluster == 0)
					break;
			}

			current_cluster = next_cluster;
		}

		sector_number = (
			current_offset / (file->fs->bpb.bytes_per_sector)
		) % file->fs->bpb.sectors_per_cluster;
		sector_offset = current_offset % file->fs->bpb.bytes_per_sector;

		copy_length = MIN(
			file->fs->bpb.bytes_per_sector - sector_offset,
			read_end - current_offset
		);

		if (copy_length != file->fs->bpb.bytes_per_sector)
			if (read_data_sector(
				file->fs, current_cluster,
				sector_number, sector
			    ))
				break;

		memcpy(&sector[sector_offset], buffer, copy_length);

		if (write_data_sector(
				file->fs, current_cluster,
				sector_number, sector
		    ))
			break;

		buffer += copy_length;
		current_offset += copy_length;
	}

	file->entry.filesize = MAX(current_offset, file->entry.filesize);
	set_entry(file->fs, &file->location, &file->entry);

	return current_offset - offset;
}

int fat_remove(struct fat_node *file)
{
	if (file->entry.attribute & FAT_ATTR_DIRECTORY)
		return -1;

	file->entry.name[0] = FAT_DIRENT_ATTR_FREE;
	set_entry(file->fs, &file->location, &file->entry);
	free_cluster_chain(file->fs, GET_FIRST_CLUSTER(file->entry));

	return 0;
}

int fat_df(
		struct fat_filesystem *fs,
		uint32_t *total_sectors, uint32_t *used_sectors
){
	if (fs->bpb.total_sectors != 0)
		*total_sectors = fs->bpb.total_sectors;
	else
		*total_sectors = fs->bpb.total_sectors32;

	*used_sectors = *total_sectors 
		      - (fs->cluster_list.count * fs->bpb.sectors_per_cluster);

	return 0;
}

// -----------------------------------------------------------------------------
// local function
// -----------------------------------------------------------------------------
uint32_t get_sector_per_clusterN(uint32_t [][2], uint64_t , uint32_t );
uint32_t get_sector_per_cluster16(uint64_t , uint32_t );
uint32_t get_sector_per_cluster32(uint64_t , uint32_t );
uint32_t get_sector_per_cluster(enum fat_type , uint64_t, uint32_t );

void fill_fat_size(struct fat_bpb *, enum fat_type );
int fill_bpb(struct fat_bpb *, enum fat_type , sector_t , uint32_t );

enum fat_type get_fat_type(struct fat_bpb *bpb)
{
	uint32_t total_sectors, data_sector, root_sector,
		 count_of_clusters, fat_size;

	root_sector = (
		(bpb->root_entry_count * 32) + (bpb->bytes_per_sector - 1)
	) / bpb->bytes_per_sector;

	if (bpb->fat_size16 != 0)
		fat_size = bpb->fat_size16;
	else
		fat_size = bpb->bpb32.fat_size_32;

	if (bpb->total_sectors != 0)
		total_sectors = bpb->total_sectors;
	else
		total_sectors = bpb->total_sectors32;

	data_sector = total_sectors - (
		bpb->reserved_sector_count + (
			bpb->number_of_fats * fat_size
		) + root_sector
	);

	count_of_clusters = data_sector / bpb->sectors_per_cluster;

	if (count_of_clusters < 4085)
		return FAT_TYPE_FAT12;
	else if (count_of_clusters < 65525)
		return FAT_TYPE_FAT16;
	else
		return FAT_TYPE_FAT32;

	return -1;
}

struct fat_entry_location
get_entry_location(const struct fat_dir_entry *);

int fill_reserved_fat(struct fat_bpb *, byte *);
int clear_fat(struct disk_operations *, struct fat_bpb *);

int create_root(struct disk_operations *, struct fat_bpb *);

int get_fat_sector(struct fat_filesystem *, sector_t ,
			  sector_t *, uint32_t *);
int prepare_fat_sector(
		struct fat_filesystem *fs, sector_t cluster,
		sector_t *fat_sector, uint32_t *fat_entry_offset, byte *sector
){
	get_fat_sector(fs, cluster, fat_sector, fat_entry_offset);
	fs->disk->read_sector(fs->disk, *fat_sector, sector);

	if (fs->type == FAT_TYPE_FAT12 
	&& *fat_entry_offset == (fs->bpb.bytes_per_sector - 1)) {
		fs->disk->read_sector(
			fs->disk, *fat_sector + 1,
			&sector[fs->bpb.bytes_per_sector]
		);
		return 1;
	}

	return 0;
}

enum fat_eoc get_fat(struct fat_filesystem *fs, sector_t cluster)
{
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE * 2];
	sector_t fat_sector;
	uint32_t fat_entry_offset;

	prepare_fat_sector(fs, cluster, &fat_sector, &fat_entry_offset, sector);

	switch (fs->type) {
	case FAT_TYPE_FAT32:
		return (*((uint32_t *) &sector[fat_entry_offset])) 
		       & FAT_MS_EOC32;

	case FAT_TYPE_FAT16:
		return (uint32_t) (*((uint16_t *) &sector[fat_entry_offset]));

	case FAT_TYPE_FAT12:
		if (cluster % 2 == 1)
			return (uint32_t) (
				*((uint16_t *) &sector[fat_entry_offset])
				>> 4
			);
		else
			return (uint32_t) (
				*((uint16_t *) &sector[fat_entry_offset]) 
			        & FAT_MS_EOC12
			);
	}

	return -1;
}

int set_fat(struct fat_filesystem *, sector_t , uint32_t );
int fat_format(struct disk_operations *, enum fat_type );

int validate_bpb(struct fat_bpb *bpb)
{
	if ( !(bpb->jmp_boot[0] == 0xEB && bpb->jmp_boot[2] == 0x90)
	  && !(bpb->jmp_boot[0] = 0xE9))
		return -1;

	return 0;
}

int read_root_sector(struct fat_filesystem *fs, sector_t number, byte *sector)
{
	sector_t root_sector;

	root_sector = fs->bpb.reserved_sector_count + (
		fs->bpb.number_of_fats * fs->bpb.fat_size16
	);

	return fs->disk->read_sector(fs->disk, root_sector + number, sector);
}

int write_root_sector(struct fat_filesystem *, sector_t , const byte *);

sector_t calc_physical_sector(struct fat_filesystem *, sector_t , sector_t );
int read_data_sector(
		struct fat_filesystem *, sector_t , sector_t , byte *
);
int write_data_sector(
		struct fat_filesystem *, sector_t , sector_t , const byte *
);

int search_free_clusters(struct fat_filesystem *fs)
{
	uint32_t total_sectors, data_sector, root_sector,
		 count_of_clusters, fat_size, cluster;

	root_sector = (
		(fs->bpb.root_entry_count * 32) + (fs->bpb.bytes_per_sector - 1)
	) / fs->bpb.bytes_per_sector;

	if (fs->bpb.fat_size16 != 0)
		fat_size = fs->bpb.fat_size16;
	else
		fat_size = fs->bpb.bpb32.fat_size_32;

	if (fs->bpb.total_sectors != 0)
		total_sectors = fs->bpb.total_sectors;
	else
		total_sectors = fs->bpb.total_sectors32;

	data_sector = total_sectors - (
		fs->bpb.reserved_sector_count + (
			fs->bpb.number_of_fats * fat_size
		) + root_sector
	);
	count_of_clusters = data_sector / fs->bpb.sectors_per_cluster;

	for (int i = 2; i < count_of_clusters; i++) {
		cluster = get_fat(fs, i);
		if (cluster == 0x00)
			add_free_cluster(fs, i);
	}

	return 0;
}
int read_dir_from_sector(
		struct fat_filesystem *, struct fat_entry_location *,
		byte *, fat_node_add_func , void *
);

enum fat_eoc get_ms_eoc(enum fat_type );
bool is_eoc(enum fat_type , sector_t );
int add_free_cluster(struct fat_filesystem *, sector_t );
sector_t alloc_free_cluster(struct fat_filesystem * );
sector_t span_clustser_chain(struct fat_filesystem *, sector_t );
int find_entry_at_sector(
		const byte *, const byte *, uint32_t , uint32_t 
);
int find_entry_on_root(
		struct fat_filesystem *, const struct fat_entry_location *,
		const byte *, struct fat_node *
);
int find_entry_on_data(
		struct fat_filesystem *, const struct fat_entry_location *,
		const byte, struct fat_node *
);
int lookup_entry(
		struct fat_filesystem *, const struct fat_entry_location *,
		const char *, struct fat_node *
);
int set_entry(
		struct fat_filesystem *, const struct fat_entry_location *,
		const struct fat_dir_entry *
);
int insert_entry(
		const struct fat_node *, struct fat_node *, 
		enum fat_dirent_attr
);
void upper_string(char *, int );
int format_name(struct fat_filesystem *, char *);
int free_cluster_chain(struct fat_filesystem *, uint32_t );
int has_sub_entries(
		struct fat_filesystem *, const struct fat_dir_entry *
);
