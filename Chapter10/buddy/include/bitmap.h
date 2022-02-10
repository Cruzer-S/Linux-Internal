#ifndef BITMAP_H__
#define BITMAP_H__

#include <stdint.h>	// uint64_t
#include <stdbool.h>	// bool

struct bitmap;

typedef struct bitmap *Bitmap;

// 비트맵 생성과 제거 함수
Bitmap bitmap_create(uint64_t bitsize);
/* extern Bitmap __bitmap_create(uint64_t size, void *addr, int addr_size); */

// 비트맵 제거 함수
void bitmap_destroy(Bitmap );

// 비트맵 연산 관련 함수
void bitmap_clear(Bitmap map);
bool bitmap_get(Bitmap map, uint64_t pos);
void bitmap_set(Bitmap map, uint64_t pos, bool set);
bool bitmap_switch(Bitmap map, uint64_t pos);

// 비트맵 정보 출력 및 반환 함수
void bitmap_show(Bitmap map, bool high_start);
void bitmap_show_all(Bitmap map, bool high_start);
void bitmap_show_area(Bitmap map, uint64_t start, uint64_t end);
uint64_t bitmap_asize(Bitmap bitmap);
uint64_t bitmap_size(Bitmap map);
int bitmap_bytebit(void);
/* extern int __bitmap_calc_alloc_size(bool is_full_struct, uint64_t size); */

#endif
