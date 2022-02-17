#ifndef DISK_H__
#define DISK_H__

#include "cluster_list.h"

struct disk_operations {
	int (*read_sector) (struct disk_operations *, sector_t , void *);
	int (*write_sector) (struct disk_operations *, sector_t , const void *);

	sector_t number_of_sectors;
	int bytes_per_sector;
	void *pdata;
};

int disksim_init(sector_t , unsigned int, struct disk_operations* );
int disksim_uninit(struct disk_operations *);

#endif
