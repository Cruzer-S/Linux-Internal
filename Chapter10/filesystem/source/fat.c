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

#define IS_POINT_ROOT_LOCATION(LOC) ((LOC)->cluster == 0)

#define MIN(A, B) ( (A) < (B) ? (A) : (B) )
#define MAX(A, B) ( (A) > (B) ? (A) : (B) )
// -----------------------------------------------------------------------------
// local function prototype
// -----------------------------------------------------------------------------
static int fill_reserved_fat(struct fat_bpb *, byte *);
static int clear_fat(struct disk_operations *, struct fat_bpb *);
static int create_root(struct disk_operations *, struct fat_bpb *);
static int fill_bpb(struct fat_bpb *, enum fat_type , sector_t , uint32_t );

static void fill_fat_size(struct fat_bpb *, enum fat_type );

static uint32_t get_sector_per_clusterN(uint32_t [][2], uint64_t , uint32_t );
static uint32_t get_sector_per_cluster(enum fat_type , uint64_t, uint32_t );
static uint32_t get_sector_per_cluster16(uint64_t , uint32_t );
static uint32_t get_sector_per_cluster32(uint64_t , uint32_t );

static struct fat_dirent_location get_dirent_location(const struct fat_dirent * );
static int has_sub_dirents(
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
		struct fat_filesystem *, struct fat_dirent_location *,
		byte *, fat_node_add_func , void *
);

static uint32_t get_ms_eoc(enum fat_type );
static bool is_eoc(enum fat_type , sector_t );
static int add_free_cluster(struct fat_filesystem *, sector_t );
static sector_t alloc_free_cluster(struct fat_filesystem * );
static sector_t span_cluster_chain(struct fat_filesystem *, sector_t );
static int find_entry_at_sector(
		const byte *, const byte *, uint32_t , uint32_t , uint32_t *
);
static int find_entry_on_root(
		struct fat_filesystem *, const struct fat_dirent_location *,
		const char *, struct fat_node *
);
static int find_entry_on_data(
		struct fat_filesystem *, const struct fat_dirent_location *,
		const char *, struct fat_node *
);
static int lookup_dirent(
		struct fat_filesystem *, const struct fat_dirent_location *,
		const char *, struct fat_node *
);
static int write_dirent(
		struct fat_filesystem *, const struct fat_dirent_location *,
		const struct fat_dirent *
);
static int register_child_dirent(
		const struct fat_node *, struct fat_node *,
		enum fat_dirent_attr 
);

static int format_name(struct fat_filesystem *, char *);
static int free_cluster_chain(struct fat_filesystem *, uint32_t );
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
	// cluster list 를 제거한다.
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
	
	// 두 번째 cluster 의 값을 읽어 들인다. (partition status)
	// 원래는 file system 이 정상적인 상태인지를 확인하는 코드인데 FAT12 에
	// 해당하는 case 가 없으므로 아래의 if statement 가 실행될 일은 없다.
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
	// 이는 cluster_list 로 표현된다.
	search_free_clusters(fs);
	
	// root_entry 의 이름을 0x20 으로 초기화한다. 0x20 은 공백문자다.
	memset(root->entry.name, 0x20, FAT_LIMIT_ENTRY_NAME_LENGTH);
	
	return 0;
}

int fat_read_dir(struct fat_node *dir, fat_node_add_func adder, void *list)
{
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	sector_t root_sector;
	struct fat_dirent_location location;
	
	// 요청한 dirent 가 root directory entry 인지 확인
	if ((IS_POINT_ROOT_ENTRY(dir->entry))
	&&  (dir->fs->type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16)))
	{
		// FAT32 는 지원 안함
		if (dir->fs->type == FAT_TYPE_FAT32)
			return -1;

		// root dirent 에 존재 가능한 엔트리의 개수를 받아서...
		// root_sector 의 크기를 구한다. 
		struct fat_bpb *bpb = &dir->fs->bpb;
		root_sector = (
			(bpb->root_entry_count * sizeof(struct fat_dirent))
		      + (bpb->bytes_per_sector - 1)
		) / bpb->bytes_per_sector;

		// root directory 가 가질 수 있는 sector size 만큼 반복
		for (int i = 0; i < root_sector; i++) {
			read_root_sector(dir->fs, i, sector);
			location.cluster = 0;
			location.sector = i;
			location.number = 0;

			if (read_dir_from_sector(
				dir->fs, &location, sector, adder, list
			    ) != 0)
				break;
		}
	} else { // root directory 가 아니라면?
		int i = GET_FIRST_CLUSTER(dir->entry);
		do {
			// FAT12 의 경우 사실 cluster 당 sector 가 1 개라서
			// location.sector 는 언제나 0 이고 반복문은 한번만
			// 실행된다.
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

			// 다음 cluster 정보를 가져온다.
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

	// 적합한 이름으로 변경
	if (format_name(parent->fs, name))
		return -1;

	// fat_node 초기화
	memset(ret, 0x00, sizeof(struct fat_node));
	memcpy(ret->entry.name, name, FAT_LIMIT_ENTRY_NAME_LENGTH);
	ret->entry.attribute = FAT_ATTR_DIRECTORY;

	// 빈 cluster 를 할당 받고 이를 종단 cluster 로 설정한다.
	first_cluster = alloc_free_cluster(parent->fs);
	if (first_cluster == 0)
		return -1;

	set_fat_entry(parent->fs, first_cluster, get_ms_eoc(parent->fs->type));

	// 할당받은 cluster 를 fat_node entry 의 first cluster 로 등록
	SET_FIRST_CLUSTER(ret->entry, first_cluster);
	// 새로 생성한 dirent 를 root dirent 의 자식으로 등록
	result = register_child_dirent(parent, ret, FAT_DIRENT_ATTR_NO_MORE);
	if (result)
		return -1;

	// 파일 시스템을 부모로부터 계승 받는다.
	ret->fs = parent->fs;

	// dot entry 를 생성 및 부모의 자식으로 등록
	memset(&dot_node, 0x00, sizeof(struct fat_node));
	memset(dot_node.entry.name, 0x20, FAT_LIMIT_ENTRY_NAME_LENGTH);
	dot_node.entry.name[0] = '.';
	dot_node.entry.attribute = FAT_ATTR_DIRECTORY;
	// FAT_DIRENT_ATTR_OVERWRITE 를 사용하기 때문에 새로 생성된 dirent 의
	// 첫 번째 entry 는 dot entry 가 먹게 된다.
	register_child_dirent(ret, &dot_node, FAT_DIRENT_ATTR_OVERWRITE);

	// dotdot entry 를 생성 및 부모의 자식으로 등록
	memset(&dotdot_node, 0x00, sizeof(struct fat_node));
	memset(dotdot_node.entry.name, 0x20, 11);
	dotdot_node.entry.name[0] = '.';
	dotdot_node.entry.name[1] = '.';
	dotdot_node.entry.attribute = FAT_ATTR_DIRECTORY;

	// dotdot entry 의 cluster 값을 parent 의 첫 번째 cluster 로 등록
	// 부모의 위치를 정보를 알림
	SET_FIRST_CLUSTER(dotdot_node.entry, GET_FIRST_CLUSTER(parent->entry));
	register_child_dirent(ret, &dotdot_node, FAT_DIRENT_ATTR_NO_MORE); 

	return 0;
}

int fat_rmdir(struct fat_node *dir)
{
	
	// sub directory 가 있는지 확인하고, 찾았다면 -1 반환
	if (has_sub_dirents(dir->fs, &dir->entry))
		return -1;

	// 못 찾았으나 정작 삭제를 요청한 dirent 가 directory 가 아니라면
	if ( !(dir->entry.attribute & FAT_ATTR_DIRECTORY) )
		return -1;

	// dirent 의 attribute 를 free 로 변경
	dir->entry.name[0] = FAT_DIRENT_ATTR_FREE;
	// 변경된 정보를 disk 에 기록
	write_dirent(dir->fs, &dir->location, &dir->entry);
	
	// free cluster list 에 등록
	free_cluster_chain(dir->fs, GET_FIRST_CLUSTER(dir->entry));

	return 0;
}

int fat_lookup(
		struct fat_node *parent, const char *entry_name,
		struct fat_node *ret_entry
){
	struct fat_dirent_location begin;
	char formatted_name[FAT_LIMIT_ENTRY_NAME_LENGTH] = { 0, };

	begin.cluster = GET_FIRST_CLUSTER(parent->entry);
	begin.sector = 0;
	begin.number = 0;

	strncpy(formatted_name, entry_name, FAT_LIMIT_ENTRY_NAME_LENGTH);

	if (format_name(parent->fs, formatted_name))
		return -1;

	if (IS_POINT_ROOT_ENTRY(parent->entry))
		begin.cluster = 0;

	return lookup_dirent(parent->fs, &begin, formatted_name, ret_entry);
}

int fat_create(
		struct fat_node *parent, const char *entry_name,
		struct fat_node *ret_entry
){
	struct fat_dirent_location first;
	char name[FAT_LIMIT_ENTRY_NAME_LENGTH] = { 0, };

	// 이름을 형식에 맞춘다.
	strncpy(name, entry_name, FAT_LIMIT_ENTRY_NAME_LENGTH);
	if (format_name(parent->fs, name))
		return -1;

	// ret_entry 의 정보를 초기화
	memset(ret_entry, 0x00, sizeof(struct fat_node));

	// 이름만 등록
	memcpy(ret_entry->entry.name, name, FAT_LIMIT_ENTRY_NAME_LENGTH);

	// parent 의 cluster 를 가져온다.
	// sector 와 number 를 0 으로 초기화해서 
	first.cluster = GET_FIRST_CLUSTER(parent->entry);
	first.sector = 0;
	first.number = 0;

	// 같은 이름은 가진 entry 가 있는지 탐색해본다.
	if (lookup_dirent(parent->fs, &first, name, ret_entry) == 0)
		return -1;

	// 없었다면 file system 을 상속 받아 parent 의 자식으로 등록한다.
	ret_entry->fs = parent->fs;
	if (register_child_dirent(parent, ret_entry, 0))
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

	if (offset > file->entry.filesize)
		return -1;

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
		while (cluster_seq < cluster_number) {
			cluster_seq++;
			current_cluster = get_fat_entry(
				file->fs, current_cluster
			);
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
) {
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	uint32_t current_offset, current_cluster, cluster_seq = 0;
	uint32_t cluster_number, sector_number, sector_offset;
	uint32_t read_end, cluster_size, cluster_offset;

	current_cluster = GET_FIRST_CLUSTER(file->entry);
	read_end = offset + length;

	current_offset = offset;

	cluster_size = file->fs->bpb.bytes_per_sector 
		     * file->fs->bpb.sectors_per_cluster;
	cluster_offset = cluster_size;

	while (offset > cluster_offset) {
		current_cluster = get_fat_entry(file->fs, current_cluster);
		cluster_offset += cluster_size;
		cluster_seq++;
	}

	while (current_offset < read_end) {
		uint32_t copy_length;

		cluster_number = current_offset / cluster_size;
		if (current_cluster == 0) {
			current_cluster = alloc_free_cluster(file->fs);
			if (current_cluster == 0)
				return -1;

			SET_FIRST_CLUSTER(file->entry, current_cluster);
			set_fat_entry(file->fs,
				      current_cluster,
			              get_ms_eoc(file->fs->type));
		}

		while (cluster_seq < cluster_number) {
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
	write_dirent(file->fs, &file->location, &file->entry);

	return current_offset - offset;
}

int fat_remove(struct fat_node *file)
{
	// directory 면 바로 빠져 나간다.
	if (file->entry.attribute & FAT_ATTR_DIRECTORY)
		return -1;

	// file 의 ATTR 만 free 로 바꿔서 등록한다.
	file->entry.name[0] = FAT_DIRENT_ATTR_FREE;
	write_dirent(file->fs, &file->location, &file->entry);

	// 파일에 할당된 cluster 를 따라가면서 모두 할당해제한다.
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

	// root dirent sector 의 위치를 계산한다.
	root_sector = (
		(bpb->root_entry_count * sizeof(struct fat_dirent))
	      + (bpb->bytes_per_sector - 1)
	) / bpb->bytes_per_sector;

	// file allocate table 의 크기를 불러온다.
	if (bpb->fat_size16 != 0)
		fat_size = bpb->fat_size16;
	else
		fat_size = bpb->bpb32.fat_size32;

	// 전체 섹터의 개수를 불러온다.
	if (bpb->total_sectors != 0)
		total_sectors = bpb->total_sectors;
	else
		total_sectors = bpb->total_sectors32;

	// 전체 섹터 크기에서 meta data sector 를 빼서
	// file data sector 의 크기를 계산한다.
	data_sector = total_sectors - (
		bpb->reserved_sector_count
	      + (bpb->number_of_fats * fat_size)
	      + root_sector
	);

	// data sector 의 크기를 클러스터 당 섹터의 크기로 나눠서
	// 데이터 섹터에 할당된 클러스터의 크기를 구한다.
	count_of_clusters = data_sector / bpb->sectors_per_cluster;

	// 크기에 따라 FAT Filesystem 의 type 을 반환한다.
	if (count_of_clusters < 4085)
		return FAT_TYPE_FAT12;
	else if (count_of_clusters < 65525)
		return FAT_TYPE_FAT16;
	else
		return FAT_TYPE_FAT32;

	return -1;
}

struct fat_dirent_location get_dirent_location(const struct fat_dirent *dirent)
{
	struct fat_dirent_location location;

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
		// 당연히 FAT12 의 entry 크기가 12 bit 이므로
		// fat_offset 은 cluster 의 위치 1 byte + 
		// cluster 위치의 반타작인 4 bit 를 더한 결과이다.
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
) {
	// cluster 값을 통해 File Allocate Table 내에서의 fat entry 가
	// 1. 위치하는 physical sector 의 값과 
	// 2. 그 안에서의 offset 을 계산
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
	// FAT12 의 entry 크기가 12bit 이므로 sector 의 마지막 cluster 라면
	// 다음 sector 와 이어지게 된다. 따라서 2 배의 sector 를 선언한다.
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

	case FAT_TYPE_FAT12: do {
		uint8_t first, last;

		if (cluster % 2 == 0) {
			first = sector[fat_entry_offset];
			last  = (sector[fat_entry_offset + 1] & 0xF0) >> 4;
		} else {
			first = (sector[fat_entry_offset] & 0x0F) << 4;
			last  = sector[fat_entry_offset + 1];
		}

		return ( (((uint16_t) first) << 4) | last );

	} while (false);
		break;
	}

	return -1;
}

int set_fat_entry(struct fat_filesystem *fs, sector_t cluster, uint32_t value)
{
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE * 2];
	sector_t fat_sector;
	uint32_t fat_entry_offset;
	int result;

	// cluster 값을 통해 File Allocate Table 내에서 fat entry 의
	// sector 위치와 그 안에서의 offset 을 구하고 해당 sector 를 불러온다.
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
	
	case FAT_TYPE_FAT12: do {
		// endian 의 무관하게 동작할 수 있도록 바이트 단위로
		// operation 을 수행한다.
		if (cluster % 2 == 0) {
			sector[fat_entry_offset] = (value & 0xFF0) >> 4;
			sector[fat_entry_offset + 1] &= 0x0F;
			sector[fat_entry_offset + 1] |= ((value & 0x0F) << 4);
		} else {
			sector[fat_entry_offset] &= 0xF0;
			sector[fat_entry_offset] |= ((value & 0xF00) >> 8);
			sector[fat_entry_offset + 1] = value & 0xFF;
		}
		} while (false);

		break;
	}

	// 변경된 내용을 다시 디스크에 기록한다.
	fs->disk->write_sector(fs->disk, fat_sector, sector);
	if (result) {
		// result 가 true 라면 변경 사항이 다음 sector 에도
		// 영향을 주었으므로 다음 섹터 역시 디스크에 기록한다.
		fs->disk->write_sector(
			fs->disk, fat_sector + 1,
			&sector[fs->bpb.bytes_per_sector]
		);
	}

	return 0;
}

int validate_bpb(struct fat_bpb *bpb)
{
	// Jump boot code 확인, 어짜피 fill_bpb 에서 제대로 채워 넣었기
	// 때문에 패 죽여도 -1 반환 안됨
	if ( !(bpb->jmp_boot[0] == 0xEB)
	&&   !(bpb->jmp_boot[2] == 0x90)
	&&   !(bpb->jmp_boot[0] == 0xE9) )
		return -1;

	return 0;
}

int read_root_sector(struct fat_filesystem *fs, sector_t number, byte *sector)
{
	sector_t root_sector;
	sector_t fat_sector;

	// fat sector 크기를 구한다.
	fat_sector = (
		(fs->bpb.number_of_fats * fs->bpb.fat_size16)
	      + (fs->bpb.bytes_per_sector - 1)
	) / (fs->bpb.bytes_per_sector);

	// root sector 를 구해온다.
	root_sector = fs->bpb.reserved_sector_count + fat_sector;
	
	// root dirent 의 시작 섹터 + number 번째 섹터를 읽어 들인다.
	return fs->disk->read_sector(fs->disk, root_sector + number, sector);
}

int write_root_sector(
		struct fat_filesystem *fs,
		sector_t sector_number,
		const byte *sector)
{
	sector_t root_sector, fat_sector;

	fat_sector = (
		(fs->bpb.number_of_fats * fs->bpb.fat_size16)
	      + (fs->bpb.bytes_per_sector - 1)
	) / fs->bpb.bytes_per_sector;

	root_sector = fs->bpb.reserved_sector_count + fat_sector;

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
	sector_t fat_sector;

	// root dirent 를 위해 할당된 영역의 sector 크기를 계산한다.
	root_dir_sectors = (
		(fs->bpb.root_entry_count * sizeof(struct fat_dirent))
	      + (fs->bpb.bytes_per_sector - 1)
	) / fs->bpb.bytes_per_sector;

	fat_sector = (
		(fs->bpb.number_of_fats * fs->fat_size)
	      + (fs->bpb.bytes_per_sector - 1)
	) / fs->bpb.bytes_per_sector;

	// first data sector 의 위치는...
	// 1. reserved sector 의 크기
	// 2. FAT sector 크기
	// 3  root directory entries 들을 위해 할당된 섹터의 크기
	// 를 모두 더한 곳에 위치하게 된다.
	first_data_sector = fs->bpb.reserved_sector_count
	                  + fat_sector
			  + root_dir_sectors;

	// cluster_number - 2 가 의미심장한 이는 root cluster 의 시작 위치인
	// 2 를 뺀 것이다. root directory 에서 최초로 생성되는 dirent 에게
	// 할당되는 cluster 는 0x02 이다. 이는 first_data_sector 를 계산할때
	// 모두 정산되었으므로 2 가 offset 0 이다.
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
	// root entry data sector 의 다음 위치부터 읽어 들인다.
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
		(fs->bpb.root_entry_count * sizeof(struct fat_dirent))
	      + (fs->bpb.bytes_per_sector - 1)
	) / fs->bpb.bytes_per_sector;

	// fat_size 를 가져온다.
	if (fs->bpb.fat_size16 != 0)
		fat_size = fs->bpb.fat_size16;
	else
		fat_size = fs->bpb.bpb32.fat_size32;

	// total_sectors 를 가져온다.
	if (fs->bpb.total_sectors != 0)
		total_sectors = fs->bpb.total_sectors;
	else
		total_sectors = fs->bpb.total_sectors32;

	// 전체 섹터에서 메타 데이터 영역의 섹터를 빼면?
	// 당연히 데이터 섹터의 크기가 나온다.
	data_sector = total_sectors - (
		fs->bpb.reserved_sector_count + (
			fs->bpb.number_of_fats * fat_size
		) + root_sector
	);

	// 전체 클러스터 수는 당연히 전체 데이터 섹터를 클러스터 당 섹터의
	// 크기로 나누면 된다.
	count_of_clusters = data_sector / fs->bpb.sectors_per_cluster;

	// 데이터 영역을 표현하는 클러스터의 수만큼 반복을 진행한다.
	// 앞서 얘기했듯이 0 과 1 cluster 는 예약 영역이므로 2 부터 시작한다.
	for (int i = 2; i < count_of_clusters; i++) {
		// get_fat_entry 를 통해 받아오는 cluster 정보는 당연히
		// 0x00 이다. 왜냐하면 이미 clear_fat 과정에서 전부 0x00
		// 으로 초기화 했기 때문이다. 따라서 fat_read_superblock()
		// 을 호출하는 시점에서의 cluster 의 값들은 전부 0x00 이다.
		cluster = get_fat_entry(fs, i);
		if (cluster == 0x00)
			add_free_cluster(fs, i);

		// add_free_cluster() 함수를 호출해서 cluster 를 cluster_list
		// 에 쭉쭉 추가한다.
	}

	return 0;
}

int read_dir_from_sector(
		struct fat_filesystem *fs, struct fat_dirent_location *location,
		byte *sector, fat_node_add_func adder, void *list
) 
{
	unsigned int entries_per_sector;
	struct fat_dirent *dir;
	struct fat_node node;

	// 섹터 당 존재 가능한 dirent 의 개수를 계산한다. 현재 시스템 기준에서
	// bytes_per_sector 가 512 byte 이고 fat_dirent 가 32 byte 이므로
	// 한 섹터에 존재 가능한 fat dirent 의 수는 16 개이다.
	entries_per_sector = fs->bpb.bytes_per_sector
		           / sizeof(struct fat_dirent);
	dir = (struct fat_dirent *) sector;

	// 16 번 반복
	for (unsigned int i = 0; i < entries_per_sector; i++) {
		if (dir->name[0] == FAT_DIRENT_ATTR_FREE)
			/* do nothing */ ;
		else if(dir->name[0] == FAT_DIRENT_ATTR_NO_MORE) {
			// directory 의 끝을 의미하므로 -1 반환하고 탈출
			return -1;
		} else if ( !(dir->attribute & FAT_ATTR_VOLUME_ID) ) {
			// FAT_ATTR_VOLUME_ID 는 root directory 에 부여되므로
			// root directory 가 아니라면 이라는 뜻으로 해석
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

uint32_t get_ms_eoc(enum fat_type type)
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
		if (FAT_EOC12 <= (cluster_number & FAT_MS_EOC12))
			return -1;
		break;

	case FAT_TYPE_FAT16:
		if (FAT_EOC16 <= (cluster_number & FAT_MS_EOC16))
			return -1;

		break;

	case FAT_TYPE_FAT32:
		if (FAT_EOC32 <= (cluster_number & FAT_MS_EOC32))
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

	// begin 부터 last 까지 dirent 를 탐색
	for (i = begin; i < last; i++) {
		// 무명 entry 를 찾는다. 이는 has_sub_dirents 함수가
		// 사용하는 것으로 현재 디렉터리 내에 sub directory 가 있는지
		// 확인하는데 쓰인다.
		if (formatted_name == NULL) {
			// 존재하는 entry 라면
			if (entry[i].name[0] != FAT_DIRENT_ATTR_FREE
			&&  entry[i].name[0] != FAT_DIRENT_ATTR_NO_MORE)
				goto FIND_ENTRY;
		} else {
			// 동일한 attribute 의 entry 를 찾았다면
			if ((formatted_name[0] == FAT_DIRENT_ATTR_FREE
			||   formatted_name[0] == FAT_DIRENT_ATTR_NO_MORE))
				if (formatted_name[0] == entry[i].name[0])
					goto FIND_ENTRY;

			// 동일한 이름의 entry 를 찾았다면
			if ( !memcmp(entry[i].name, formatted_name,
				     FAT_LIMIT_ENTRY_NAME_LENGTH)   )
				goto FIND_ENTRY;
		}

		// 암것도 안 걸렸는데 attribute 마저 no more 라면
		if (entry[i].name[0] == FAT_DIRENT_ATTR_NO_MORE)
			goto DOESNT_EXIST;
	} goto CANT_NOT_FIND;

CANT_NOT_FIND: return -1;
DOESNT_EXIST:  return -2;
FIND_ENTRY:    *number = i;
	       return 0;
}

int find_entry_on_root(
		struct fat_filesystem *fs,
		const struct fat_dirent_location *first,
		const char *formatted_name,
		struct fat_node *ret
) {
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	uint32_t number;
	uint32_t last_sector;
	uint32_t entries_per_sector, last_entry;
	int32_t begin, result;
	struct fat_dirent *entry;
	
	// entries_per_sector: 당연히 16.
	// last_entry: 1 을 빼는데 이는 no more entry 를 위함
	// last_sector: 마지막 entry 도 root entry count 를 
	//              섹터 당 엔트리로 나눠서 계산
	entries_per_sector = fs->bpb.bytes_per_sector
		           / sizeof(struct fat_dirent);
	last_entry = entries_per_sector;
	last_sector = fs->bpb.root_entry_count / entries_per_sector;

	// dirent location 으로 부터 sector 내의 index 를 구한다.
	begin = first->number;

	// first sector 부터 last sector 사이에 있는 모든 dirent 를 읽는다.
	for (uint32_t i = first->sector; i <= last_sector; i++) {
		// sector 로 부터 데이터를 읽어온다.
		read_root_sector(fs, i, sector);

		// sector 로부터 첫 번째 dirent 의 주소를 가져온다.
		entry = (struct fat_dirent *) sector;

		// 다시 find_entry_at_sector 로 jump
		result = find_entry_at_sector(
			sector, (byte *) formatted_name,
			begin, last_entry, &number
		);
		// 이제 다시 begin 은 0 으로 초기화
		begin = 0;

		// result == -1: 현재 섹터엔 없지만 이게 directory entry 의
		//               끝은 아니므로 다음 섹터를 찾아봐!
		if (result == -1)
			continue;

		// result == -2: 야 마지막 dirent 야 빠져나와
		if (result == -2)
			return -1;

		// 찾았다면 ret->entry 를 발견한 entry 로 대입
		// ret->entry = entry[number];
		memcpy(&ret->entry, &entry[number], sizeof(struct fat_dirent));

		// location 의
		ret->location.cluster = 0;
		ret->location.sector = i;
		ret->location.number = number;

		// ret 의 filesystem 등록
		ret->fs = fs;

		// 0 반환: 성공적으로 찾았음
		return 0;
	}

	// 끝까지 뒤졌는데 그런거 없음
	return -1;
}

int find_entry_on_data(
		struct fat_filesystem *fs,
		const struct fat_dirent_location *first,
		const char *formatted_name,
		struct fat_node *ret
) {
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	uint32_t number;
	uint32_t entries_per_sector, last_entry;
	uint32_t start_sector, current_cluster;
	int32_t begin;
	int32_t result;
	struct fat_dirent *entry;

	// 원본 데이터를 유지해야 하기 때문에
	// 추적에 사용할 시작 위치 정보를 따로 저장
	begin = first->number;
	current_cluster = first->cluster;
	start_sector = first->sector;

	entries_per_sector = fs->bpb.bytes_per_sector
			   / sizeof(struct fat_dirent);
	last_entry = entries_per_sector;

	while (true) {
		uint32_t next_cluster;

		// 요청한 첫 sector 부터 cluster 끝까지 탐색
		for (uint32_t i = start_sector;
		     i < fs->bpb.sectors_per_cluster;
		     i++)
		{
			// sector 의 데이터를 읽어온다.
			read_data_sector(fs, current_cluster, i, sector);

			// entry 를 sector 의 주소로 초기화
			entry = (struct fat_dirent *) sector;

			// sector 내에서 dirent 의 탐색을 시작
			result = find_entry_at_sector(
				sector, (byte *) formatted_name,
				begin, last_entry, &number
			);

			// 끝났다면 begin 을 0 으로 초기화
			begin = 0;

			// 해당 sector 를 조사 했는데 당장 없었다면
			if (result == -1)
				continue;

			// no more entry 가 떴다면
			if (result == -2)
				return -2;

			// 찾았다면
			memcpy(&ret->entry,
			       &entry[number],
			       sizeof(struct fat_dirent));

			// 위치 정보 등록
			ret->location.cluster = current_cluster;
			ret->location.sector = i;
			ret->location.number = number;

			// 파일 시스템 등록
			ret->fs = fs;

			return 0;
		}

		// 다음 cluster 정보를 가져옴
		next_cluster = get_fat_entry(fs, current_cluster);

		// End of cluster 라면 반복 중단
		if (is_eoc(fs->type, next_cluster))
			break;
		else if (next_cluster == 0)
			break;

		// 다음 cluster 가 있다면 start_sector 를 0 으로 초기화하고
		// 처음부터 다시 진행
		start_sector = 0;
		current_cluster = next_cluster;
	}

	return -1;
}

int lookup_dirent(
		struct fat_filesystem *fs,
		const struct fat_dirent_location *first,
		const char *entry_name,
		struct fat_node *ret
) {
	// first 의 cluster 가 0 이라는 것 --> root dirent area 에 포함된
	// dirent 객체라는 것을 의미한다.
	if ( (first->cluster == 0                        )
	&&   (fs->type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16) ) )
	{
		return find_entry_on_root(fs, first, entry_name, ret);
	} else {
		return find_entry_on_data(fs, first, entry_name, ret);
	}
	
	return -1;
}

int write_dirent(
		struct fat_filesystem *fs,
		const struct fat_dirent_location *location,
		const struct fat_dirent *value
){
	byte sector[FAT_LIMIT_MAX_SECTOR_SIZE];
	struct fat_dirent *entry;

	// location->cluster == 0 이라는 것은
	// 해당 dirent 가 root dirent area 에 속해있는 원소임을
	// 의미하는 것이다.
	if ( (location->cluster == 0                      )
	&&   (fs->type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16)) ) {
		read_root_sector(fs, location->sector, sector);

		// location 을 통해 찾은 dirent 위치에
		// 인자로 전달한 value 값을 대입
		entry = (struct fat_dirent *) sector;
		entry[location->number] = *value;

		// 변경된 dirent 정보를 디스크에 작성
		write_root_sector(fs, location->sector, sector);
	} else { // root sector 가 아니라면 data sector 에서 값을 읽어온다.
		read_data_sector(
			fs, location->cluster, location->sector, sector
		);

		// 이하 동문
		entry = (struct fat_dirent *) sector;
		entry[location->number] = *value;

		write_data_sector(
			fs, location->cluster, location->sector, sector
		);
	}

	return 0;
}

int register_child_dirent(
		const struct fat_node *parent, struct fat_node *new_entry, 
		enum fat_dirent_attr overwrite
) {
	struct fat_dirent_location begin;
	struct fat_node entry_no_more;
	byte entry_name[2] = { 0, };
	const struct fat_bpb *bpb;
	const struct fat_dirent *dirent;
	const enum fat_type *type;
	struct fat_filesystem *fs;

	// 부모의 cluster 를 가져옴
	begin.cluster = GET_FIRST_CLUSTER(parent->entry);
	begin.sector = 0;
	begin.number = 0;

	// 부모로부터 온갖 정보를 다 빼옴
	bpb = &parent->fs->bpb;
	dirent = &parent->entry;
	type = &parent->fs->type;
	fs = parent->fs;

	// parent 가 root directory 가 아니면서
	// overwrite 속성 역시 FAT_DIRENT_ATTR_NO_MORE 가 아니라면?
	if ( ( !(IS_POINT_ROOT_ENTRY(*dirent))		 )
	&&   ( *type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16) )
	&&   ( overwrite != FAT_DIRENT_ATTR_NO_MORE)     ) {
		// 첫 번째 엔트리로 등록한다.
		begin.number = 0;
		write_dirent(fs, &begin, &new_entry->entry);
		new_entry->location = begin;

		// 그 다음 index 의 entry 는 no more entry 로 설정한다.
		begin.number = 1;
		memset(&entry_no_more, 0x00 ,sizeof(struct fat_node));
		entry_no_more.entry.name[0] = FAT_DIRENT_ATTR_NO_MORE;
		write_dirent(fs, &begin, &entry_no_more.entry);

		// 끝!
		return 0;
	}

	// 비어있는 dirent 를 탐색한다.
	entry_name[0] = FAT_DIRENT_ATTR_FREE;
	if (lookup_dirent(fs, &begin, (char *) entry_name, &entry_no_more) == 0)
	{
		// 찾았다면 그 위치를 new_entry 로 변경
		write_dirent(fs, &entry_no_more.location, &new_entry->entry);
		// location 도 새롭게 찾은 위치로 변경
		new_entry->location = entry_no_more.location;

		// 탈출
		return 0;
	}

	// 위에서 비어있는 dirent 를 못 찾았다.
	// 근데 이게 웬걸? 부모가 root 네? Hoxy 너...
	if ( ( IS_POINT_ROOT_ENTRY(*dirent)              )
	&&   ( *type & (FAT_TYPE_FAT12 | FAT_TYPE_FAT16) ) ) {
		uint32_t root_entry_count;

		root_entry_count = new_entry->location.sector * (
			bpb->bytes_per_sector / sizeof(struct fat_dirent)
		) + new_entry->location.number;

		// root entry count 가 bpb->root_entry_count 보다 크거나 같다면
		// => new_entry 가 root dirent 의 마지막 끝단 dirent 라면
		if (root_entry_count >= bpb->root_entry_count)
			return -1;
	}

	// no more entry 를 찾는데
	entry_name[0] = FAT_DIRENT_ATTR_NO_MORE;
	if (lookup_dirent(fs, &begin, (char *) entry_name, &entry_no_more) != 0)
		// 못 찾았다면 빠져 나간다. 이건 뭔가 이상한 상황이다.
		return -1;

	// 찾았다면 no_more entry 위치에 new entry 를 집어 넣는다.
	write_dirent(fs, &entry_no_more.location, &new_entry->entry);
	new_entry->location = entry_no_more.location;

	// no more entry 의 index 를 증가 시킨다
	entry_no_more.location.number++;

	// 만일 no more entry 가 sector 내의 마지막 index 였다면...?
	if ( ( entry_no_more.location.number                     )
	==   ( bpb->bytes_per_sector / sizeof(struct fat_dirent) ) )
	{
		// no more entry 의 sector 를 증가시키고
		entry_no_more.location.sector++;
		// index 를 0 으로 바꿔 다음 sector 로 옳길 준비를 한다.
		entry_no_more.location.number = 0;

		// 근데 여기서 또 이 sector 가 cluster 의 크기와 같다?
		// => cluster 내의 마지막 sector 라면
		if (entry_no_more.location.sector == bpb->sectors_per_cluster)
		{
			// root directory 가 아닌 경우에만
			// cluster 를 늘린다.
			// root dirent 의 경우 root dirent cluster 로부터
			// 선형적으로 늘어나기 때문에 새로운 cluster 를
			// 할당받을 필요가 없다. 또한 언제나 cluster 값이
			// 0 으로 고정이므로 sector 와 number 만 설정해주면
			// 된다.
			if ( !IS_POINT_ROOT_ENTRY(*dirent) ) {
				// span_cluster_chain 함수를 호출해서
				// 다음 cluster 값을 받아오고 이를
				// no more entry 의 cluster 값으로 설정
				entry_no_more.location.cluster =
					span_cluster_chain(
						fs,
						entry_no_more.location.cluster
					);

				// 실패했다?
				if (entry_no_more.location.cluster == 0)
					// 답이 없다.
					return -1;

				// 성공했다면 sector 를 0 으로 초기화
				entry_no_more.location.sector = 0;
			}
		}
	}

	// no_more_entry 다시 기록
	write_dirent(fs, &entry_no_more.location, &entry_no_more.entry);

	return 0;
}

int free_cluster_chain(struct fat_filesystem *fs, uint32_t first_cluster)
{
	uint32_t current_cluster = first_cluster;
	uint32_t next_cluster;

	// current_cluster 가 end of cluster 도 free cluster 도 아니라면
	while ( !is_eoc(fs->type, current_cluster) && current_cluster != 0x00) {
		// 다음 cluster 위치를 가져오고
		next_cluster = get_fat_entry(fs, current_cluster);
		// 현재 cluster 를 free cluster 로 설정
		set_fat_entry(fs, current_cluster, 0x00);
		// free cluster 를 cluster list 에 등록
		add_free_cluster(fs, current_cluster);
		// 현재 cluster 를 next cluster 로 변경
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

int has_sub_dirents(struct fat_filesystem *fs, const struct fat_dirent *dirent)
{
	struct fat_dirent_location begin;
	struct fat_node sub_entry;

	// 현재 directory 의 location 을 가져온 후
	begin = get_dirent_location(dirent);
	// 두 번째 entry 부터 시작해서 (dot 과 dotdot 을 무시하겠다는 의미)
	begin.number = 2;

	// format_name 을 NULL 로 주고 탐색을 수행한다.
	// FAT_DIRENT_ATTR_FREE 와 FAT_DIRENT_ATTR_NO_MORE 로 설정되지 않은
	// => 존재하는 entry 를 찾는다.
	if ( !lookup_dirent(fs, &begin, NULL, &sub_entry) )
		return 1;

	// 찾았으면 0
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
	uint8_t *shut_errbit12;
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
		shut_errbit12 = (uint8_t *) sector;

		// 1 바이트씩 작성하지 않으면 사용 중인 system 의 endian 에 
		// 따라 값이 거꾸로 저장될 수도 있다. 이는 이후 get_fat_entry()
		// 함수 호출 시에 치명적인 문제를 발생시킬 수 있으므로
		// 반드시 1 byte 씩 읽고 써야 한다.
		*(shut_errbit12++) = 0xFF;
		*(shut_errbit12)   = (bpb->media & 0x0F) << 4;

		*(shut_errbit12++) |= ((uint16_t) FAT_MS_EOC12 >> 8) & 0x0F;
		*(shut_errbit12) = (uint16_t) FAT_MS_EOC12 & 0xFF;
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
	sector_t root_sector = 0, fat_sector;
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
		fat_sector = (
			(bpb->number_of_fats * bpb->fat_size16)
		      + (bpb->bytes_per_sector - 1)
		) / bpb->bytes_per_sector;
		// 루트 엔트리의 섹터 위치는 매우 쉽게 계산 가능하다.
		// reserved area + FAT 크기 => root entry 시작 위치
		root_sector = bpb->reserved_sector_count + fat_sector;
	}

	// root directory entry 를 disk 에 기록한다.
	disk->write_sector(disk, root_sector, sector);

	return 0;
}
