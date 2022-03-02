#include "fat.h"

#include <stdio.h>	// for the printf()
#include <string.h>	// for the memset()
#include <ctype.h>	// for the isalnum()

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
	(ENTRY).first_cluster_hi = ((CLUSTER) >> 16);				\
	(ENTRY).first_cluster_lo = (uint16_t) ((CLUSTER) & 0xFFFF);		\
} while (false)

#define MIN(A, B) ( (A) < (B) ? (A) : (B) )
#define MAX(A, B) ( (A) > (B) ? (A) : (B) )
// -----------------------------------------------------------------------------
// local function prototype
// -----------------------------------------------------------------------------
static int fill_reserved_fat(struct fat_bpb *, byte *);
static int create_root(struct disk_operations *, struct fat_bpb *);
static void fill_fat_size(struct fat_bpb *, enum fat_type );

static uint32_t get_sector_per_clusterN(uint32_t [][2], uint64_t , uint32_t );
static uint32_t get_sector_per_cluster(enum fat_type , uint64_t, uint32_t );
static uint32_t get_sector_per_cluster16(uint64_t , uint32_t );
static uint32_t get_sector_per_cluster32(uint64_t , uint32_t );

static struct fat_entry_location get_entry_location(const struct fat_dirent * );
static int has_sub_entries(
		struct fat_filesystem *, const struct fat_dirent *
);
static enum fat_type get_fat_type(struct fat_bpb *);
static int get_fat_sector(
		struct fat_filesystem *, sector_t , sector_t *, uint32_t *
);
static int prepare_fat_sector(
		struct fat_filesystem *, sector_t ,
		sector_t *, uint32_t *, byte *
);

static int clear_fat(struct disk_operations *, struct fat_bpb *);

static uint32_t get_fat_entry(struct fat_filesystem *, sector_t );
static int set_fat_entry(struct fat_filesystem *, sector_t , uint32_t );
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
static sector_t span_cluster_chain(struct fat_filesystem *, sector_t );
static int find_entry_at_sector(
		const byte *, const byte *, uint32_t , uint32_t , uint32_t *
);
static int find_entry_on_root(
		struct fat_filesystem *, const struct fat_entry_location *,
		const char *, struct fat_node *
);
static int find_entry_on_data(
		struct fat_filesystem *, const struct fat_entry_location *,
		const char *, struct fat_node *
);
static int lookup_entry(
		struct fat_filesystem *, const struct fat_entry_location *,
		const char *, struct fat_node *
);
static int set_entry(
		struct fat_filesystem *, const struct fat_entry_location *,
		const struct fat_dirent *
);
static int insert_entry(
		const struct fat_node *, struct fat_node *,
		enum fat_dirent_attr 
);

static int format_name(struct fat_filesystem *, char *);
static int free_cluster_chain(struct fat_filesystem *, uint32_t );
static int fill_bpb(struct fat_bpb *, enum fat_type , sector_t , uint32_t );
// -----------------------------------------------------------------------------
// global function
// -----------------------------------------------------------------------------
int fat_format(struct disk_operations *disk, enum fat_type type)
{
	struct fat_bpb bpb;

	// bpb 에 기본적인 내용을 채워 넣는다.
	if (fill_bpb(&bpb, type, disk->number_of_sectors, 
		     disk->bytes_per_sector) != 0)
		return -1;

	// 위 내용을 0번째 sector 에 기록한다. bpb 의 크기 역시 512 bytes 이다.
	// reserved area 의 초기화라고 생각하면 된다.
	disk->write_sector(disk, 0, &bpb);

	printf("bytes per sector: %u\n", bpb.bytes_per_sector);
	printf("sectors per cluster: %u\n", bpb.sectors_per_cluster);
	printf("number of FATs: %u\n", bpb.number_of_fats);
	printf("root entry count: %u\n", bpb.root_entry_count);
	printf("total sectors: %u\n", bpb.total_sectors ? bpb.total_sectors 
				                        : bpb.total_sectors32);
	putchar('\n');

	// reserved area 다음 영역인 FAT 영역의 초기화를 진행한다.
	// 초기화된 FAT 영역을 디스크에 기록한다.
	clear_fat(disk, &bpb);

	// FAT 의 다음 영역인, root directory entry 를 생성하고
	// 이를 디스크에 기록한다.
	create_root(disk, &bpb);

	return 0;
}

void fat_umount(struct fat_filesystem *fs)
{
	cluster_list_release(&fs->cluster_list);
}

int fat_read_superblock(struct fat_filesystem *fs, struct fat_node *root)
{
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];

	if (fs == NULL || fs->disk == NULL)
		return -1;

	// reserved area 를 디스크로부터 읽어 들인다. 이는 앞서
	// fill_bpb 를 통해 구성한 내용이다.
	if (fs->disk->read_sector(fs->disk, 0, &fs->bpb))
		return -1;

	// bpb 의 유효성을 검사한다.
	if (validate_bpb(&fs->bpb) != 0)
		return -1;

	// bpb 를 통해 사용하고 있는 FAT 파일 시스템의 타입 정보를 추출한다.
	fs->type = get_fat_type(&fs->bpb);
	// FAT32 는 아직 지원하지 않으므로 -1 반환
	if (fs->type == FAT_TYPE_FAT32)
		return -1;

	// 루트 디렉터리 엔트리 섹터를 읽어 들인다.
	if (read_root_sector(fs, 0, sector))
		return -1;

	// root 노드를 0x00 으로 초기화하고...
	memset(root, 0x00, sizeof(struct fat_node));
	// root 노드의 dirent 를 root dirent 로 초기화한다.
	memcpy(&root->entry, sector, sizeof(struct fat_dirent));
	// root 의 filesystem 을 인자로 받아온 filesystem 으로 초기화
	root->fs = fs;

	// 첫 번째 cluster 의 값을 읽어 들인다.
	// 원래 아래의 코드가 실행되어야 하는데 FAT12 시스템으로
	// 아래의 if statement 가 실행될 일은 없다.
	fs->eoc_mark = get_fat_entry(fs, 1);
	if (fs->type == FAT_TYPE_FAT32) {
		if (fs->eoc_mark & (FAT_BIT_MASK16_SHUT | FAT_BIT_MASK32_ERR))
			return -1;
	} else if (fs->type == FAT_TYPE_FAT16) {
		if (fs->eoc_mark & (FAT_BIT_MASK16_SHUT | FAT_BIT_MASK16_ERR))
			return -1;
	}

	
	// fat_size16 의 값이 0 이 아니라면 (FAT32 가 아니라면)
	if (fs->bpb.fat_size16 != 0)
		fs->fat_size = fs->bpb.fat_size16;
	// fat_size16 의 값이 0 이라면 (FAT32 라면)
	else
		fs->fat_size = fs->bpb.bpb32.fat_size32;

	// cluster_list 를 초기화한다.
	cluster_list_init(&fs->cluster_list);

	// free cluster 를 찾아 다니면서 cluster chain 을 구성한다.
	search_free_clusters(fs);

	memset(root->entry.name, 0x20, FAT_LIMIT_ENTRY_NAME_LENGTH);

	return 0;
}

int fat_read_dir(struct fat_node *dir, fat_node_add_func adder, void *list)
{
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	sector_t root_entry_count;
	struct fat_entry_location location;

	if ((IS_POINT_ROOT_ENTRY(dir->entry))
	&&  (dir->fs->type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16)))
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

			i = get_fat_entry(dir->fs, i);
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
	memcpy(ret->entry.name, name, FAT_LIMIT_ENTRY_NAME_LENGTH);
	ret->entry.attribute = FAT_ATTR_DIRECTORY;
	first_cluster = alloc_free_cluster(parent->fs);

	if (first_cluster == 0)
		return -1;

	set_fat_entry(parent->fs, first_cluster, get_ms_eoc(parent->fs->type));

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

	return lookup_entry(parent->fs, &begin, formatted_name, ret_entry);
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
		current_cluster = get_fat_entry(file->fs, current_cluster);
		cluster_offset += cluster_size;

		cluster_seq++;
	}

	while (current_offset < read_end)
	{
		uint32_t copy_length;

		cluster_number = current_offset / cluster_size;
		if (cluster_seq != cluster_number) {
			cluster_seq++;
			current_cluster = get_fat_entry(file->fs, current_cluster);
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
		current_cluster = get_fat_entry(file->fs, current_cluster);
		cluster_size += cluster_size;
		cluster_seq ++;
	}

	while (current_offset < read_end) {
		uint32_t copy_length;

		cluster_number = current_offset / (
			file->fs->bpb.bytes_per_sector 
		      * file->fs->bpb.sectors_per_cluster
		);
		if (current_cluster == 0) {
			current_cluster = alloc_free_cluster(file->fs);
			if (current_cluster == 0)
				return -1;

			SET_FIRST_CLUSTER(file->entry, current_cluster);
			set_fat_entry(file->fs,
				      current_cluster,
			              get_ms_eoc(file->fs->type));
		}

		if (cluster_seq != cluster_number) {
			uint32_t next_cluster;
			cluster_seq++;

			next_cluster = get_fat_entry(file->fs, current_cluster);
			if (is_eoc(file->fs->type, next_cluster)) {
				next_cluster = span_cluster_chain(
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
		fat_size = bpb->bpb32.fat_size32;

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

struct fat_entry_location get_entry_location(const struct fat_dirent *dirent)
{
	struct fat_entry_location location;

	location.cluster = GET_FIRST_CLUSTER(*dirent);
	location.sector = 0;
	location.number = 0;

	return location;
}

int get_fat_sector(struct fat_filesystem *fs, sector_t cluster,
		   sector_t *fat_sector, uint32_t *fat_entry_offset)
{
	uint32_t fat_offset;

	switch(fs->type) {
	case FAT_TYPE_FAT32:
		fat_offset = cluster * 4;
		break;

	case FAT_TYPE_FAT16:
		fat_offset = cluster * 2;
		break;

	case FAT_TYPE_FAT12:
		// 요청한 cluster 에 대한 fat_offset 을 계산한다.
		fat_offset = cluster + (cluster / 2);
		break;

	default:
		fat_offset = 0;
		break;
	}

	// *fat_sector 는 reserved_sector_count + (offset / sector_size) 로
	// 계산되어 진다.
	*fat_sector = fs->bpb.reserved_sector_count + (
		fat_offset / fs->bpb.bytes_per_sector
	);

	// fat_entry_offset 은 fat_offset 을 sector size 로 나눈 나머지로
	// 구할 수 있다.
	*fat_entry_offset = fat_offset % fs->bpb.bytes_per_sector;

	return 0;
}

int prepare_fat_sector(
		struct fat_filesystem *fs, sector_t cluster,
		sector_t *fat_sector, uint32_t *fat_entry_offset, byte *sector
){
	// cluster 를 통해 fat 의 sector 위치와 sector 내에서의 offset 을 계산.
	get_fat_sector(fs, cluster, fat_sector, fat_entry_offset);

	// 앞서 구한 sector 를 바탕으로 디스크에서 데이터를 긁어온다.
	fs->disk->read_sector(fs->disk, *fat_sector, sector);

	// 만일 fs 의 type 이 FAT12 이면서 fat_entry 의 offset 이 
	// sector size - 1 과 같다면 그 다음 sector 또한 읽어 들인다.
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

uint32_t get_fat_entry(struct fat_filesystem *fs, sector_t cluster)
{
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE * 2];
	sector_t fat_sector;
	uint32_t fat_entry_offset;

	// cluster 를 통해 fat 의 sector 위치와 sector 내의 offset 을 계산한다.
	prepare_fat_sector(fs, cluster, &fat_sector, &fat_entry_offset, sector);

	switch (fs->type) {
	case FAT_TYPE_FAT32:
		return (*((uint32_t *) &sector[fat_entry_offset])) 
		       & FAT_MS_EOC32;

	case FAT_TYPE_FAT16:
		return (uint32_t) (*((uint16_t *) &sector[fat_entry_offset]));

	case FAT_TYPE_FAT12:
		// 만일 cluster 가 홀수라면
		if (cluster % 2 == 1)
			// sector 의 fat_entry_offset 위치의 값을 읽어 들인다.
			// FAT12 의 FAT entry 크기는 12 bit 이므로, 먼저
			// offset 기준으로 2byte 를 읽고 앞에 4 bit 를 자른다.
			return (uint32_t) (
				*((uint16_t *) &sector[fat_entry_offset])
				>> 4
			);
		// 홀수라면 반대로 동작한다. 앞의 12 bit 를 읽고 뒤의 4 bit 를
		// 짤라낸다.
		else
			return (uint32_t) (
				*((uint16_t *) &sector[fat_entry_offset]) 
			        & FAT_MS_EOC12
			);
	}

	return -1;
}

int set_fat_entry(struct fat_filesystem *fs, sector_t cluster, uint32_t value)
{
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE * 2];
	sector_t fat_sector;
	uint32_t fat_entry_offset;
	int result;

	result = prepare_fat_sector(
		fs, cluster, &fat_sector, &fat_entry_offset, sector
	);

	switch(fs->type) {
	case FAT_TYPE_FAT32:
		value &= FAT_MS_EOC32;
		*((uint32_t *) &sector[fat_entry_offset] ) &= 0xF0000000;
		*((uint32_t *) &sector[fat_entry_offset] ) |= value;
		break;

	case FAT_TYPE_FAT16:
		*((uint16_t *) &sector[fat_entry_offset]) = (uint16_t) value;
		break;
	
	case FAT_TYPE_FAT12:
		if (cluster & 0x01) {
			value <<= 4;
			*((uint16_t *) &sector[fat_entry_offset]) &= 0x000F;
		} else {
			value &= 0x0FFF;
			*((uint16_t *) &sector[fat_entry_offset]) &= 0xF000;
		}

		*((uint16_t *) &sector[fat_entry_offset]) |= (uint16_t) value;
		break;
	}

	fs->disk->write_sector(fs->disk, fat_sector, sector);
	if (result) {
		fs->disk->write_sector(
			fs->disk, fat_sector + 1,
			&sector[fs->bpb.bytes_per_sector]
		);
	}

	return 0;
}

int validate_bpb(struct fat_bpb *bpb)
{
	if ( !(bpb->jmp_boot[0] == 0xEB && bpb->jmp_boot[2] == 0x90)
	&&   !(bpb->jmp_boot[0] == 0xE9                            ))
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

int write_root_sector(
		struct fat_filesystem *fs,
		sector_t sector_number,
		const byte *sector)
{
	sector_t root_sector;

	root_sector = fs->bpb.reserved_sector_count + (
		fs->bpb.number_of_fats * fs->bpb.fat_size16
	);

	return fs->disk->write_sector(
		fs->disk, root_sector + sector_number, sector
	);
}

sector_t calc_physical_sector(
		struct fat_filesystem *fs, sector_t cluster_number,
		sector_t sector_number
){
	sector_t first_data_sector;
	sector_t first_sector_of_cluster;
	sector_t root_dir_sectors;

	root_dir_sectors = (
		(fs->bpb.root_entry_count * 32) 
	      + (fs->bpb.bytes_per_sector - 1)
	) / fs->bpb.bytes_per_sector;

	first_data_sector = fs->bpb.reserved_sector_count 
	                  + (fs->bpb.number_of_fats * fs->fat_size)
			  + root_dir_sectors;

	first_sector_of_cluster = (
		(cluster_number - 2) * fs->bpb.sectors_per_cluster
	) + first_data_sector;

	return first_sector_of_cluster + sector_number;
}

int read_data_sector(
		struct fat_filesystem *fs, sector_t cluster_number,
		sector_t sector_number, byte *sector
)
{
	return fs->disk->read_sector(
		fs->disk, calc_physical_sector(
			fs, cluster_number, sector_number
		), sector
	);

	return 0;
}

int write_data_sector(
		struct fat_filesystem *fs, sector_t cluster_number,
		sector_t sector_number, const byte *sector
){
	return fs->disk->write_sector(
		fs->disk, calc_physical_sector(
			fs, cluster_number, sector_number
		), sector
	);
}

int search_free_clusters(struct fat_filesystem *fs)
{
	uint32_t total_sectors, data_sector, root_sector,
		 count_of_clusters, fat_size, cluster;

	// root entry 가 존재하는 root sector 의 위치를 계산한다.
	root_sector = (
		(fs->bpb.root_entry_count * 32) + (fs->bpb.bytes_per_sector - 1)
	) / fs->bpb.bytes_per_sector;

	if (fs->bpb.fat_size16 != 0)
		fat_size = fs->bpb.fat_size16;
	else
		fat_size = fs->bpb.bpb32.fat_size32;

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
		cluster = get_fat_entry(fs, i);
		if (cluster == 0x00)
			add_free_cluster(fs, i);
	}

	return 0;
}

int read_dir_from_sector(
		struct fat_filesystem *fs, struct fat_entry_location *location,
		byte *sector, fat_node_add_func adder, void *list
)
{
	unsigned int entries_per_sector;
	struct fat_dirent *dir;
	struct fat_node node;

	entries_per_sector = fs->bpb.bytes_per_sector
		           / sizeof(struct fat_dirent);
	dir = (struct fat_dirent *) sector;

	for (unsigned int i = 0; i < entries_per_sector; i++) {
		if (dir->name[0] == FAT_DIRENT_ATTR_FREE)
			/* do nothing */ ;
		else if(dir->name[0] == FAT_DIRENT_ATTR_NO_MORE)
			return -1;
		else if ( !(dir->attribute & FAT_ATTR_VOLUME_ID) ) {
			node.fs = fs;
			node.location = *location;
			node.location.number = i;
			node.entry = *dir;
			adder(list, &node);
		}

		dir++;
	}

	return 0;
}

enum fat_eoc get_ms_eoc(enum fat_type type)
{
	switch (type) {
	case FAT_TYPE_FAT12:
		return FAT_MS_EOC12;
	case FAT_TYPE_FAT16:
		return FAT_MS_EOC16;
	case FAT_TYPE_FAT32:
		return FAT_MS_EOC32;
	}

	return -1;
}

bool is_eoc(enum fat_type type, sector_t cluster_number)
{
	switch (type) {
	case FAT_TYPE_FAT12:
		if (FAT_EOC12 <= (cluster_number & 0x0FFF))
			return -1;
		break;

	case FAT_TYPE_FAT16:
		if (FAT_EOC16 <= (cluster_number & 0xFFFF))
			return -1;

		break;

	case FAT_TYPE_FAT32:
		if (FAT_EOC32 <= (cluster_number & 0x0FFFFFFF))
			return -1;
		break;
	}

	return 0;
}

int add_free_cluster(struct fat_filesystem *fs, sector_t cluster)
{
	return cluster_list_push(&fs->cluster_list, cluster);
}

sector_t alloc_free_cluster(struct fat_filesystem * fs)
{
	sector_t cluster;

	if ( cluster_list_pop(&fs->cluster_list, &cluster) != 0 )
		return 0;

	return cluster;
}

sector_t span_cluster_chain(struct fat_filesystem *fs, sector_t cluster_number)
{
	uint32_t next_cluster;

	next_cluster = alloc_free_cluster(fs);

	if (next_cluster) {
		set_fat_entry(fs, cluster_number, next_cluster);
		set_fat_entry(fs, next_cluster, get_ms_eoc(fs->type));
	}

	return next_cluster;
}

int find_entry_at_sector(
		const byte *sector, const byte *formatted_name,
		uint32_t begin, uint32_t last, uint32_t *number
){
	const struct fat_dirent *entry;
	uint32_t i;

	entry = (struct fat_dirent *) sector;

	for (i = begin; i < last; i++) {
		if (formatted_name == NULL) {
			if (entry[i].name[0] != FAT_DIRENT_ATTR_FREE 
			&&  entry[i].name[0] != FAT_DIRENT_ATTR_NO_MORE) {
				*number = i;
				return 0;
			}
		} else {
			if ((formatted_name[0] == FAT_DIRENT_ATTR_FREE
			||   formatted_name[0] == FAT_DIRENT_ATTR_NO_MORE)) {
				if (formatted_name[0] == entry[i].name[0]) {
					*number = i;
					return 0;
				}
			}

			if ( !memcmp(entry[i].name, formatted_name,
				     FAT_LIMIT_ENTRY_NAME_LENGTH)   )  {
				*number = i;
				return 0;
			}
		}

		if (entry[i].name[0] == FAT_DIRENT_ATTR_NO_MORE) {
			*number = i;
			return -2;
		}
	}

	*number = i;

	return -1;
}

int find_entry_on_root(
		struct fat_filesystem *fs,
		const struct fat_entry_location *first,
		const char *formatted_name,
		struct fat_node *ret
){
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	uint32_t number;
	uint32_t last_sector;
	uint32_t entries_per_sector, last_entry;
	int32_t begin, result;
	struct fat_dirent *entry;

	begin = first->number;
	entries_per_sector = fs->bpb.bytes_per_sector
		           / sizeof(struct fat_dirent);
	last_entry = entries_per_sector - 1;
	last_sector = fs->bpb.root_entry_count / entries_per_sector;

	for (uint32_t i = first->sector; i <= last_sector; i++) {
		read_root_sector(fs, i, sector);
		entry = (struct fat_dirent *) sector;

		result = find_entry_at_sector(
			sector, (byte *) formatted_name,
			begin, last_entry, &number
		);
		begin = 0;

		if (result == -1)
			continue;

		if (result == -2)
			return -1;

		memcpy(&ret->entry, &entry[number], sizeof(struct fat_dirent));

		ret->location.cluster = 0;
		ret->location.sector = i;
		ret->location.number = number;

		ret->fs = fs;

		return 0;
	}

	return -1;
}

int find_entry_on_data(
		struct fat_filesystem *fs,
		const struct fat_entry_location *first,
		const char *formatted_name,
		struct fat_node *ret
) {
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	uint32_t number;
	uint32_t entries_per_sector, last_entry;
	uint32_t current_cluster;
	int32_t begin;
	int32_t result;
	struct fat_dirent *entry;

	begin = first->number;
	current_cluster = first->cluster;
	entries_per_sector = fs->bpb.bytes_per_sector
			   / sizeof(struct fat_dirent);
	last_entry = entries_per_sector - 1;

	while (true) {
		uint32_t next_cluster;

		for (uint32_t i = first->sector;
		     i < fs->bpb.sectors_per_cluster;
		     i++)
		{
			read_data_sector(fs, current_cluster, i, sector);
			entry = (struct fat_dirent *) sector;

			result = find_entry_at_sector(
				sector, (byte *) formatted_name,
				begin, last_entry, &number
			);

			begin = 0;

			if (result == -1)
				continue;

			if (result == -2)
				return -1;

			memcpy(&ret->entry,
			       &entry[number],
			       sizeof(struct fat_dirent));

			ret->location.cluster = current_cluster;
			ret->location.sector = i;
			ret->location.number = number;

			ret->fs = fs;

			return 0;
		}

		next_cluster = get_fat_entry(fs, current_cluster);

		if (is_eoc(fs->type, next_cluster))
			break;
		else if (next_cluster == 0)
			break;

		current_cluster = next_cluster;
	}

	return -1;
}

int lookup_entry(
		struct fat_filesystem *fs,
		const struct fat_entry_location *first,
		const char *entry_name,
		struct fat_node *ret
){
	if ( (first->cluster == 0)
	&&   (fs->type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16) ))
	{
		return find_entry_on_root(fs, first, entry_name, ret);
	} else {
		return find_entry_on_data(fs, first, entry_name, ret);
	}
	
	return 0;
}

int set_entry(
		struct fat_filesystem *fs,
		const struct fat_entry_location *location,
		const struct fat_dirent *value
){
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	struct fat_dirent *entry;

	if ( (location->cluster == 0)
	&&   (fs->type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16))) {
		read_root_sector(fs, location->sector, sector);

		entry = (struct fat_dirent *) sector;
		entry[location->number] = *value;

		write_root_sector(fs, location->sector, sector);
	} else {
		read_data_sector(
			fs, location->cluster, location->sector, sector
		);

		entry = (struct fat_dirent *) sector;
		entry[location->number] = *value;

		write_data_sector(
			fs, location->cluster, location->sector, sector
		);
	}

	return 0;
}

int insert_entry(
		const struct fat_node *parent, struct fat_node *new_entry, 
		enum fat_dirent_attr overwrite
)
{
	struct fat_entry_location begin;
	struct fat_node entry_no_more;
	byte entry_name[2] = { 0, };
	const struct fat_bpb *bpb;
	const struct fat_dirent *dirent;
	const enum fat_type *type;
	struct fat_filesystem *fs;

	begin.cluster = GET_FIRST_CLUSTER(parent->entry);
	begin.sector = 0;
	begin.number = 0;

	bpb = &parent->fs->bpb;
	dirent = &parent->entry;
	type = &parent->fs->type;
	fs = parent->fs;

	if ( ( !(IS_POINT_ROOT_ENTRY(*dirent))		 )
	&&   ( *type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16) ) 
	&&   ( overwrite != FAT_DIRENT_ATTR_NO_MORE)     ) {
		begin.number = 0;

		set_entry(fs, &begin, &new_entry->entry);
		new_entry->location = begin;

		begin.number = 1;
		memset(&entry_no_more, 0x00 ,sizeof(struct fat_node));
		entry_no_more.entry.name[0] = FAT_DIRENT_ATTR_NO_MORE;
		set_entry(fs, &begin, &entry_no_more.entry);

		return 0;
	}

	entry_name[0] = FAT_DIRENT_ATTR_FREE;
	if (lookup_entry(fs, &begin, (char *) entry_name, &entry_no_more) == 0)
	{
		set_entry(fs, &entry_no_more.location, &new_entry->entry);
		new_entry->location = entry_no_more.location;

		return 0;
	}

	if ( ( IS_POINT_ROOT_ENTRY(*dirent)              )
	&&   ( *type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16) ) ) {
		uint32_t root_entry_count;

		root_entry_count = new_entry->location.sector * (
			bpb->bytes_per_sector / sizeof(struct fat_dirent)
		) + new_entry->location.number;

		if (root_entry_count >= bpb->root_entry_count)
			return -1;
	}

	entry_name[0] = FAT_DIRENT_ATTR_NO_MORE;
	if (lookup_entry(fs, &begin, (char *) entry_name, &entry_no_more) != 0)
		return -1;

	set_entry(fs, &entry_no_more.location, &new_entry->entry);
	new_entry->location = entry_no_more.location;
	entry_no_more.location.number++;

	if ( ( entry_no_more.location.number                     )
	==   ( bpb->bytes_per_sector / sizeof(struct fat_dirent) ) )
	{
		entry_no_more.location.sector++;
		entry_no_more.location.number = 0;

		if (entry_no_more.location.sector == bpb->sectors_per_cluster)
		{
			if( ( !(IS_POINT_ROOT_ENTRY(*dirent))           )
			&&  ( *type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16) ) ) 
			{
				entry_no_more.location.cluster =
					span_cluster_chain(
						fs,
						entry_no_more.location.cluster
					);

				if (entry_no_more.location.cluster == 0)
					return -1;

				entry_no_more.location.sector = 0;
			}
		}
	}

	set_entry(fs, &entry_no_more.location, &entry_no_more.entry);

	return 0;
}

int free_cluster_chain(struct fat_filesystem *fs, uint32_t first_cluster)
{
	uint32_t current_cluster = first_cluster;
	uint32_t next_cluster;

	while ( !is_eoc(fs->type, current_cluster) && current_cluster != 0x00) {
		next_cluster = get_fat_entry(fs, current_cluster);
		set_fat_entry(fs, current_cluster, 0x00);
		add_free_cluster(fs, current_cluster);
		current_cluster = next_cluster;
	}

	return 0;
}

int format_name(struct fat_filesystem *fs, char *name)
{
	uint32_t length;
	uint32_t extender, name_length;
	uint32_t extender_current;
	byte regular_name[FAT_LIMIT_ENTRY_NAME_LENGTH];

	extender = 0;
	name_length = 0;
	extender_current = 8;

	memset(regular_name, 0x20, sizeof(regular_name));
	length = strlen(name);

	if (strncmp(name, "..", 2) == 0) {
		memcpy(name, "..         ", FAT_LIMIT_ENTRY_NAME_LENGTH);
		return 0;
	} else if (strncmp(name, ".", 1) == 0) {
		memcpy(name, ".          ", FAT_LIMIT_ENTRY_NAME_LENGTH);
		return 0;
	}

	if (fs->type != FAT_TYPE_FAT32) {
		for (uint32_t i = 0; i < length; i++) {
			if (name[i] != '.' && !isalnum(name[i]))
				return -1;

			if (name[i] == '.') {
				if (extender)
					return -1;

				extender = 1;
			} else if ( isalnum(name[i]) ) {
				if (extender)
					regular_name[
						extender_current++
					] = name[i];
				else
					regular_name[name_length++] = name[i];
			} else {
				return -1;
			}
		}

		if (name_length > 8 || name_length == 0
		||  extender_current > FAT_LIMIT_ENTRY_NAME_LENGTH)
			return -1;
	}

	memcpy(name, regular_name, sizeof(regular_name));

	return 0;
}

int has_sub_entries(struct fat_filesystem *fs, const struct fat_dirent *dirent)
{
	struct fat_entry_location begin;
	struct fat_node sub_entry;

	begin = get_entry_location(dirent);
	begin.number = 2;

	if ( !lookup_entry(fs, &begin, NULL, &sub_entry) )
		return -1;

	return 0;
}

const char *fat_type_to_string(enum fat_type type)
{
	switch (type) {
	case FAT_TYPE_FAT12: return "FAT12";
	case FAT_TYPE_FAT16: return "FAT16";
	case FAT_TYPE_FAT32: return "FAT32";
	}

	return NULL;
}

int fill_bpb(
		struct fat_bpb *bpb, enum fat_type type,
		sector_t number_of_sectors, uint32_t bytes_per_sector
) {
	uint64_t disk_size = number_of_sectors * bytes_per_sector;
	uint32_t sectors_per_cluster;
	struct fat_boot_sector *bs;

	if (type > FAT_TYPE_FAT32)
		return -1;

	memset(bpb, 0x00, sizeof(struct fat_bpb));

	// jmp code 를 삽입
	bpb->jmp_boot[0] = 0xEB;
	bpb->jmp_boot[1] = 0x00;
	bpb->jmp_boot[2] = 0x90;

	// OEM 이름, 필자 이름으로 박아 넣었다.
	memcpy(bpb->oem_name, "mythos", 8);

	// 클러스터 당 섹터의 수를 계산한다.
	sectors_per_cluster = get_sector_per_cluster(
		type, disk_size, bytes_per_sector
	);
	if (sectors_per_cluster == 0) {
		return -1;
	}

	// 섹터 당 바이트
	bpb->bytes_per_sector = bytes_per_sector;
	// 클러스터 당 섹터 수
	bpb->sectors_per_cluster = sectors_per_cluster;
	// 예약된 섹터 크기 (맨 앞의 BPB 하나가 있으므로 당연히 1 이다.)
	bpb->reserved_sector_count = ((type == FAT_TYPE_FAT32) ? 32 : 1);
	// FAT 의 수인데 일반적으론 백업본까지 합쳐 두 개이지만
	// 필자의 예에서는 1 개만 존재한다.
	bpb->number_of_fats = 1;
	// root directory 가 가질 수 있는 entry 의 개수
	// FAT32 에서는 사용하지 않으므로 0 으로 초기화
	bpb->root_entry_count = ((type == FAT_TYPE_FAT32) ? 0 : 512);
	// 전체 섹터의 수
	bpb->total_sectors = ( (number_of_sectors < 0x10000)
			   ?   (uint16_t) number_of_sectors : 0 );

	// media 는 장치의 특성을 의미하는 0xF8 은 고정 디스크를 의미한다.
	// HDD 정도로 이해하면 될 듯 하다.
	bpb->media = 0xF8;

	// FAT 의 크기를 계산한다.
	fill_fat_size(bpb, type);

	// 디스크 관련 정보인데 0 으로 초기화 한다.
	bpb->sectors_per_track = 0;
	bpb->number_of_heads = 0;
	// 전체 섹터의 수
	bpb->total_sectors32 = (number_of_sectors >= 0x10000 
			     ? number_of_sectors : 0);

	// FAT32 정보 초기화, FAT12 에선 사용되지 않음
	if (type == FAT_TYPE_FAT32) {
		bpb->bpb32.exflags = 0x0081;
		bpb->bpb32.filesystem_version = 0;
		bpb->bpb32.root_cluster = 2;
		bpb->bpb32.filesystem_info = 1;
		bpb->bpb32.backup_boot_sectors = 6;
		bpb->bpb32.backup_boot_sectors = 0;
		memset(bpb->bpb32.reserved, 0x00, 12);
	}

	// bs 초기화
	if (type == FAT_TYPE_FAT32)
		bs = &bpb->bpb32.bs;
	else
		bs = &bpb->bs;

	// drive number 초기화
	if (type == FAT_TYPE_FAT12)
		bs->drive_number = 0x00;
	else
		bs->drive_number = 0x80;

	// 부트 시그니쳐 초기화
	bs->reserved1 = 0;
	bs->boot_signature = 0x29;
	bs->volume_id = 0;

	// 볼륨 레이블 초기화
	memcpy(bs->volume_label, "mythos fat", 11);

	// 파일 시스템 정보 초기화
	memcpy(bs->filesystem_type, fat_type_to_string(type), 8);

	return 0;
}

uint32_t get_sector_per_cluster(
		enum fat_type type, uint64_t disk_size,
		uint32_t bytes_per_sector
) {
	switch(type) {
	case FAT_TYPE_FAT12:
		return 1;

	case FAT_TYPE_FAT16:
		return get_sector_per_cluster16(disk_size, bytes_per_sector);

	case FAT_TYPE_FAT32:
		return get_sector_per_cluster32(disk_size, bytes_per_sector);
	}

	return 0;
}

uint32_t get_sector_per_cluster16(uint64_t disk_size, uint32_t bytes_per_sector)
{
	uint32_t disk_table_fat16[][2] = {
		{ 8400,		0	},
		{ 32680,	2	},
		{ 262144,	4	},
		{ 524288,	8	},
		{ 1048576,	16	},
		{ 2097152,	32	},
		{ 4194304,	64	},
		{ 0xFFFFFFFF,	0	}
	};

	return get_sector_per_clusterN(
		disk_table_fat16, disk_size, bytes_per_sector
	);
}

uint32_t get_sector_per_cluster32(uint64_t disk_size, uint32_t bytes_per_sector)
{
	uint32_t disk_table_fat32[][2] = {
		{ 66600,	0	},
		{ 532480,	1	},
		{ 16777216,	8	},
		{ 33554432,	16	},
		{ 67108864,	32	},
		{ 0xFFFFFFFF,	64	}
	};

	return get_sector_per_clusterN(
		disk_table_fat32, disk_size, bytes_per_sector
	);
}

uint32_t get_sector_per_clusterN(
		uint32_t disk_table[][2], uint64_t disk_size,
		uint32_t bytes_per_sector
) {
	int i = 0;

	do {
		if ( ((uint64_t) (disk_table[i][0] * 512)) >= disk_size )
			return disk_table[i][1] / (bytes_per_sector / 512);
	} while (disk_table[i++][0] < 0xFFFFFFFF);

	return 0;
}

void fill_fat_size(struct fat_bpb *bpb, enum fat_type type)
{
	// 말 그대로 disk 크기에 맞는 섹터의 수
	uint32_t disk_size = (bpb->total_sectors32 == 0 ? bpb->total_sectors 
			                                : bpb->total_sectors32);
	// root directory entry 를 위해 할당되는 sector 의 수
	// root_entry_count 는 root dirent 가 가질 수 있는 directory entry 의
	// 크기로 default 로 512 이고 dirent 의 크기는 32 bytes 이다.
	// 이를 섹터의 크기(512 bytes) 로 나누면 필요한 섹터의 크기를 구할 수
	// 있게 되고 이는 (512 * 32) / 512  = 32 가 된다.
	uint32_t root_dir_sectors = (
		(bpb->root_entry_count * sizeof(struct fat_dirent))
	      + (bpb->bytes_per_sector - 1)
	) / bpb->bytes_per_sector;

	// 아래의 수식은 Microsoft 에서 제공하는 공식 문서의 계산 방법인데
	// 정확하게 딱 맞는 크기는 아니고 조금 넉넉하게 크기를 잡는다.
	uint32_t tmp1 = disk_size - (
		bpb->reserved_sector_count + root_dir_sectors
	),	 tmp2 = (256 * bpb->sectors_per_cluster) + bpb->number_of_fats;
	uint32_t fat_size;

	if (type == FAT_TYPE_FAT32)
		tmp2 = tmp2 / 2;

	fat_size = (tmp1 + (tmp2 - 1)) / tmp2;

	if (type == FAT_TYPE_FAT32) {
		bpb->fat_size16 = 0;
		bpb->bpb32.fat_size32 = fat_size;
	} else {
		bpb->fat_size16 = (uint16_t) fat_size & 0xFFFF;
	}
}

int clear_fat(struct disk_operations *disk, struct fat_bpb *bpb)
{
	uint32_t end;
	uint32_t fat_size;
	sector_t fat_sector;
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];

	// File Allocate Table 을 작성하기 위한 512 byte 섹터를 초기화
	memset(sector, 0x00, sizeof(sector));

	// fat_sector 위치 = reserved area 의 크기
	fat_sector = bpb->reserved_sector_count;

	// fat_size 는 앞서 fill_fat_size() 로 계산한 값
	if (bpb->fat_size16 != 0)
		fat_size = bpb->fat_size16;
	else
		fat_size = bpb->bpb32.fat_size32;

	// FAT 영역의 시작과 끝은 fat_sector ~ end 가 된다.
	end = fat_sector + (fat_size * bpb->number_of_fats);

	// FAT 의 1, 2 번째 cluster 는 예약되어 있다.
	// 1: Media Type
	// 2: Partition Status
	// fill_reserved_fat() 는 이를 초기화해주는 함수이다.
	fill_reserved_fat(bpb, sector);
	
	// reserved cluster 를 디스크에 기록한다.
	disk->write_sector(disk, fat_sector, sector);

	// 예약된 cluster 를 제외한 나머지 영역은 모두 0x00 으로 초기화한다.
	memset(sector, 0x00, sizeof(sector));
	for (uint32_t i = fat_sector + 1; i < end; i++)
		disk->write_sector(disk, i, sector);

	return 0;
}

int fill_reserved_fat(struct fat_bpb *bpb, byte *sector)
{
	enum fat_type type;
	uint32_t *shut_errbit12;
	uint16_t *shut_bit16;
	uint16_t *err_bit16;
	uint32_t *shut_bit32;
	uint32_t *err_bit32;

	type = get_fat_type(bpb);
	switch (type) {
	case FAT_TYPE_FAT12:
		// FAT12 의 각 FAT entry 의 크기는 12 비트이고,
		// FAT 의 앞 두 엔트리가 예약 영역이므로 24 bit = 3 byte 
		// 로 계산할 수 있다.
		shut_errbit12 = (uint32_t *) sector;

		// 아래의 값을 쓰게 되면
		// 0xFF8FFF 00 00000000 ......
		// 이 된다.
		*shut_errbit12 = 0xFF0 << 20;
		*shut_errbit12 |= ((uint32_t) bpb->media & 0x0F) << 20;
		*shut_errbit12 |= FAT_MS_EOC12 << 8;
		break;

	case FAT_TYPE_FAT16:
		shut_bit16 = (uint16_t *) sector;
		err_bit16 = (uint16_t *) sector + sizeof(uint16_t);

		*shut_bit16 = 0xFFF0 | bpb->media;
		*err_bit16 = FAT_MS_EOC16;
		break;

	case FAT_TYPE_FAT32:
		shut_bit32 = (uint32_t *) sector;
		err_bit32 = (uint32_t *) sector + sizeof(uint32_t);

		*shut_bit32 = 0x0FFFFFFF0 | bpb->media;
		*err_bit32 = FAT_MS_EOC32;
		break;
	}

	return 0;
}

int create_root(struct disk_operations *disk, struct fat_bpb *bpb)
{
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	sector_t root_sector = 0;
	struct fat_dirent *entry;

	// 먼저 sector 를 모두 0x00 으로 초기화하고...
	memset(sector, 0x00, FAT_LIMIT_MAX_SECTOR_SIZE);
	// sector 로부터 dirent 구조체를 위한 메모리를 가져와
	entry = (struct fat_dirent *) sector;

	// root directory entry 를 구성한다.
	memcpy(entry->name, "mythos fat", FAT_LIMIT_ENTRY_NAME_LENGTH);
	entry->attribute = FAT_ATTR_VOLUME_ID;

	(++entry)->name[0] = FAT_DIRENT_ATTR_NO_MORE;
	if (get_fat_type(bpb) == FAT_TYPE_FAT32) {
		/* Not implemented yet */
	} else {
		// 루트 엔트리의 섹터 위치는 매위 쉽게 계산 가능하다.
		// reserved area + FAT 크기 => root entry 시작 위치
		root_sector = bpb->reserved_sector_count + (
			bpb->number_of_fats * bpb->fat_size16
		);
	}

	// root directory entry 를 disk 에 기록한다.
	disk->write_sector(disk, root_sector, sector);

	return 0;
}
