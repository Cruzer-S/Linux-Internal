#include "disksim.h"

#include <stdlib.h>	// for malloc(), free()
#include <string.h>	// for memcpy()

struct disk_memory {
	void *address;
};

int disksim_read(struct disk_operations *ops, sector_t sector, void *data);
int disksim_write(struct disk_operations *ops, sector_t sector, const void *data);

int disksim_init(
	sector_t number_of_sectors,
	unsigned int bytes_per_sector,
	struct disk_operations *disk)
{
	if (disk == NULL)
		goto RETURN_ERR;

	disk->pdata = malloc(sizeof(struct disk_memory));
	if (disk->pdata == NULL)
		goto DISKSIM_UNINIT;

	((struct disk_memory *) disk->pdata) -> address = malloc(
		bytes_per_sector * number_of_sectors
	);

	if (((struct disk_memory *) disk->pdata) -> address == NULL)
		goto FREE_DISK_PDATA;

	disk->read_sector = disksim_read;
	disk->write_sector = disksim_write;
	disk->number_of_sectors = number_of_sectors;
	disk->bytes_per_sector = bytes_per_sector;

	return 0;

FREE_DISK_PDATA:free(disk->pdata);
DISKSIM_UNINIT:	disksim_uninit(*disk);
RETURN_ERR:	return -1;
}

int disksim_read(struct disk_operations *disk, sector_t sector, void *data)
{
	char *disk_addr;
	int index;

	if (sector < 0 || sector >= disk->number_of_sectors)
		return -1;

	disk_addr = ((struct disk_memory *) disk->pdata ) -> address;
	index = sector * disk->bytes_per_sector;

	memcpy(data, &disk_addr[index], disk->bytes_per_sector);

	return 0;
}

int disksim_write(
		struct disk_operations *disk,
		sector_t sector,
		const void *data
) {
	char *disk_addr;
	int index;

	if (sector < 0 || sector >= disk->number_of_sectors)
		return -1;

	disk_addr = ((struct disk_memory *) disk->pdata ) -> address;
	index = sector * disk->bytes_per_sector;

	memcpy(&disk_addr[index], data, disk->bytes_per_sector);

	return 0;
}

void disksim_uninit(struct disk_operations ops)
{
	if (ops.pdata) {
		free ( ((struct disk_memory *) ops.pdata)->address );
		free(ops.pdata);
	}
}
