// -----------------------------------------------------------------------------
// source file macro
// -----------------------------------------------------------------------------
#define _POSIX_C_SOURCE 200809L

// -----------------------------------------------------------------------------
// include own header
// -----------------------------------------------------------------------------
#include "shell_filesystem.h"

// -----------------------------------------------------------------------------
// include user-defined header
// -----------------------------------------------------------------------------
#include "fat.h"

// -----------------------------------------------------------------------------
// include c standard library
// -----------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// -----------------------------------------------------------------------------
// local function
// -----------------------------------------------------------------------------
static char *stpncpy_ex(char *dest, char *orig, char *stop, int size)
{
	while ( ( *orig != EOF                  ) 
	&&      ( (strchr(stop, *orig)) == NULL )
	&&      ( (size--) > 0                  ) )
		*dest++ = *orig++;

	return dest;
}
static int fat_entry_to_shell_entry(
		const struct fat_node *fat_entry,
		struct shell_entry *shell_entry
) {
	struct fat_node *entry = (struct fat_node *) shell_entry->pdata;
	char *str;

	memset(shell_entry, 0x00, sizeof(struct shell_entry));
	if (entry->entry.attribute != FAT_ATTR_VOLUME_ID) {
		str = shell_entry->name;
		str = stpncpy_ex(str, (char *) fat_entry->entry.name, " ", 8);
		if (fat_entry->entry.name[8] != 0x20) {
			str = stpncpy_ex(str, ".", " ", 1);
			str = stpncpy_ex(
				str, (char *) &fat_entry->entry.name[8], " ", 3
			);
		}
	}

	if (fat_entry->entry.attribute & FAT_ATTR_DIRECTORY
	||  fat_entry->entry.attribute & FAT_ATTR_VOLUME_ID) 
	{
		shell_entry->is_dir = 1;
	} else {
		shell_entry->size = fat_entry->entry.filesize;
	}

	*entry = *fat_entry;

	return 0;
}

static int fs_create(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		const struct shell_entry *parent, const char *name,
		struct shell_entry *ret
) {
	struct fat_node *fat_parent, fat_entry;
	int result;

	fat_parent = (struct fat_node *) parent->pdata;
	result = fat_create(fat_parent, name, &fat_entry);
	*((struct fat_node *) ret->pdata) = fat_entry;

	return result;
}

static int fs_remove(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		const struct shell_entry *parent, const char *name
) {
	struct fat_node file;

	if (fat_lookup((struct fat_node *) parent->pdata, name, &file) != 0)
		return -1;

	return fat_remove(&file);
}

static int fs_read(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		const struct shell_entry *parent,
		const struct shell_entry *entry,
		unsigned long offset ,unsigned long length, char *buffer
) {
	return fat_read((struct fat_node *) entry->pdata, offset, length, buffer);
}

static int fs_write(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		const struct shell_entry *parent, struct shell_entry *entry,
		unsigned long offset, unsigned long length, const char *buffer
) {
	return fat_write((struct fat_node *) entry->pdata, offset, length, buffer);
}

static int fs_stat(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		unsigned int *total_sectors, unsigned int *used_sectors
) {
	return fat_df(
		(struct fat_filesystem *) (fops->pdata),
		total_sectors,
		used_sectors
	);
}

static int adder(void *list, struct fat_node *entry)
{
	struct shell_entry_list *entry_list = (struct shell_entry_list *) list;
	struct shell_entry new_entry;

	fat_entry_to_shell_entry(entry, &new_entry);
	shell_entry_list_add(entry_list, &new_entry);

	return 0;
}

static int fs_read_dir(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		const struct shell_entry *parent, struct shell_entry_list *list
) {
	struct fat_node entry;
	if (list->count)
		shell_entry_list_release(list);

	entry = *((struct fat_node *) parent->pdata);
	fat_read_dir(&entry, adder, list);

	return 0;
}

static bool is_exist(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		const struct shell_entry *parent, const char *name)
{
	struct shell_entry_list list;
	bool find = false;

	shell_entry_list_init(&list);
	fs_read_dir(disk, fops, parent, &list);

	LIST_ITERATOR_WITH_ENTRY(list.head, entry, struct shell_entry, list)
		if (strncmp(entry->name, name, 12) == 0) {
			find = true;
			LIST_ITERATOR_BREAK;
		}
	LIST_ITERATOR_END

	shell_entry_list_release(&list);
	return find;
}

static int fs_mkdir(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		struct shell_entry *parent, const char *name,
		struct shell_entry *ret
) {
	struct fat_node fat_parent;
	struct fat_node fat_entry;
	int result;

	if (is_exist(disk, fops, parent, name))
		return -1;

	fat_parent = *((struct fat_node *) parent->pdata);
	result = fat_mkdir(&fat_parent, name, &fat_entry);
	fat_entry_to_shell_entry(&fat_entry, ret);

	return result;
}

static int fs_rmdir(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		const struct shell_entry *parent, const char *name
) {
	struct fat_node fat_parent;
	struct fat_node dir;

	fat_parent = *((struct fat_node *) parent->pdata);
	if (fat_lookup(&fat_parent, name, &dir) != 0)
		return -1;

	return fat_rmdir(&dir);
}

static int fs_lookup(
		struct disk_operations *disk, struct shell_fs_operations *fops,
		const struct shell_entry *parent, struct shell_entry *entry,
		const char *name
) {
	struct fat_node fat_parent, fat_entry;
	int result;

	fat_parent = *((struct fat_node *) parent->pdata);
	result = fat_lookup(&fat_parent, name, &fat_entry);
	fat_entry_to_shell_entry(&fat_entry, entry);

	return result;
}
/*******************************************************************************
 * export function
 ******************************************************************************/
int fs_mount(
		struct disk_operations *disk, struct shell_fs_operations *fops, 
		struct shell_entry *root)
{
	struct fat_filesystem *fat;
	struct fat_node fat_entry;
	int result;
	char vol_label[12] = { 0, };

	*fops = (struct shell_fs_operations) {
		.read_dir	= fs_read_dir,
		.stat		= fs_stat,
		.mkdir		= fs_mkdir,
		.rmdir		= fs_rmdir,
		.lookup		= fs_lookup,
		.file_ops	= (struct shell_file_operations) {
			.create	 = fs_create,
			.read	 = fs_read,
			.write	 = fs_write,
			.remove	 = fs_remove
		},
		.pdata		= NULL
	};

	
	fops->pdata = malloc(sizeof(struct fat_filesystem));
	if (fops->pdata == NULL)
		return -1;

	fat = (struct fat_filesystem *) fops->pdata;
	memset(fat, 0x00, sizeof(struct fat_filesystem));
	fat->disk = disk;
	result = fat_read_superblock(fat, &fat_entry);
	if (result == 0) {
		if (fat->type == FAT_TYPE_FAT16)
			memcpy(vol_label, fat->bpb.bpb32.bs.volume_label, 11);
		else
			memcpy(vol_label, fat->bpb.bs.volume_label, 11);

		printf("%-12s: %s\n", "FAT type",
				      fat_type_to_string(fat->type));
		printf("%-12s: %s\n", "volume label", vol_label);
		printf("%-12s: %d\n", "bytes per sector",
				      fat->bpb.bytes_per_sector);
		printf("%-12s: %d\n", "sectors per cluster",
				      fat->bpb.sectors_per_cluster);
		printf("%-12s: %d\n", "number of FATs",
				      fat->bpb.number_of_fats);
		printf("%-12s: %d\n", "root entry count",
				      fat->bpb.root_entry_count);
		printf("%-12s: %d\n", "total sectors",
			(fat->bpb.total_sectors ? fat->bpb.total_sectors
						: fat->bpb.total_sectors32));
		putchar('\n');
	}

	fat_entry_to_shell_entry(&fat_entry, root);

	return result;
}

void fs_umount(struct disk_operations *disk, struct shell_fs_operations *fops)
{
	if (fops && fops->pdata) {
		fat_umount((struct fat_filesystem *) fops->pdata);
		free(fops->pdata);
		fops->pdata = 0;
	}
}

int fs_format(struct disk_operations *disk, void *param)
{
	char *fat_type_string[3] = {
		"FAT12", "FAT16", "FAT32"
	};
	enum fat_type fat_type[3] = {
		FAT_TYPE_FAT12, FAT_TYPE_FAT16, FAT_TYPE_FAT32
	};
	int type_idx;
	char *param_str = (char *) param;

	if (param) {
		int i;
		for (i = 0; i < 3; i++) {
			if (strncmp(param_str, fat_type_string[i], 100) == 0) {
				type_idx = i;
				break;
			}
		}

		if (i == 3) {
			printf("unkown FAT type\n");
			return -1;
		}
	} else {
		if (disk->number_of_sectors <= 8400)
			type_idx = 0;
		else if (disk->number_of_sectors <= 66600)
			type_idx = 1;
		else
			type_idx = 2;
	}

	printf("formatting as a %s\n", fat_type_string[type_idx]);

	return fat_format(disk, fat_type[type_idx]);
}
/*******************************************************************************
 * export function
 ******************************************************************************/
void shell_register_filesystem(struct shell_filesystem *fs)
{
	*fs = (struct shell_filesystem) {
		.name = "FAT",
		.mount = fs_mount,
		.umount = fs_umount,
		.format = fs_format
	};
}
