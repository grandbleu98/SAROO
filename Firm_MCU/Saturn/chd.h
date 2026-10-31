#ifndef SAROO_CHD_H
#define SAROO_CHD_H

#include <stdint.h>

typedef int (*CHD_READ_FN)(void *opaque, uint64_t offset,
                           void *buffer, uint32_t length);

typedef struct {
    uint8_t type;
    uint32_t length;
    uint64_t offset;
    uint16_t crc;
} CHD_MAP_ENTRY;

typedef struct {
    void *opaque;
    CHD_READ_FN read;
    uint64_t file_size;
    uint64_t logical_bytes;
    uint32_t hunk_bytes;
    uint32_t unit_bytes;
    uint32_t hunk_count;
    uint32_t compression[4];
    CHD_MAP_ENTRY *map;
} CHD_CTX;

enum {
    CHD_OK = 0,
    CHD_ERR_ARGUMENT = -1,
    CHD_ERR_IO = -2,
    CHD_ERR_FORMAT = -3,
    CHD_ERR_MAP = -4,
    CHD_ERR_MEMORY = -5,
    CHD_ERR_CODEC = -6,
    CHD_ERR_PARENT = -7
};

int chd_v5_open(CHD_CTX *ctx, void *opaque, CHD_READ_FN read_fn,
                uint64_t file_size);
void chd_v5_close(CHD_CTX *ctx);
int chd_v5_read_hunk(CHD_CTX *ctx, uint32_t hunk, uint8_t *dest);

#endif
