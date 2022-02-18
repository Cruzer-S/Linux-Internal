#include "fat_shell.h"

struct fat_entry {
	union {
		uint16_t half_cluster[2];
		uint32_t full_cluster;
	};

	byte attribute;
};
