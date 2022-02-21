#ifndef SHELL_FILESYSTEM_H__
#define SHELL_FILESYSTEM_H__

#include "disksim.h"
#include "shell_entry.h"

struct shell_fs_operations {
	int (*read_dir) (
			struct disk_operations *, struct shell_fs_operations *,
			const struct shell_entry *, struct shell_entry_list *
	);

	int (*stat) (
			struct disk_operations *, struct shell_fs_operations *,
			unsigned int *, unsigned int *
	);

	int (*mkdir) (
			struct disk_operations *, struct shell_fs_operations *,
			struct shell_entry *, const char *, struct shell_entry *
	);

	int (*rmdir) (
			struct disk_operations *, struct shell_fs_operations *,
			const struct shell_entry *, const char *
	);

	int (*lookup)(
			struct disk_operations *, struct shell_fs_operations *,
			const struct shell_entry *, struct shell_entry *,
			const char *
	);

	struct shell_file_operations *file_ops;
	void *pdata;
};

struct shell_file_operations {
	int (*create)(
			struct disk_operations *, struct shell_fs_operations *,
			const struct shell_entry *, const char *,
			struct shell_entry *
	);

	int (*remove)(
			struct disk_operations *, struct shell_fs_operations *,
			const struct shell_entry *, const char *
	);

	int (*read)(
			struct disk_operations *, struct shell_fs_operations *,
			const struct shell_entry *, const struct shell_entry *,
			unsigned long, unsigned long, char *
	);

	int (*write)(
			struct disk_operations *, struct shell_fs_operations *,
			const struct shell_entry *, struct shell_entry *,
			unsigned long, unsigned long, const char *
	);
};

struct shell_filesystem {
	char *name;
	int (*mount) (
		struct disk_operations *, struct shell_fs_operations *,
		struct shell_entry *
	);
	void (*umount) (struct disk_operations *, struct shell_fs_operations *);
	int (*format) (struct disk_operations *, void *);
};

#endif
