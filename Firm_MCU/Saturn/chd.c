#include "chd.h"
#include <stdlib.h>
#include <string.h>

#define CHD_V5_HEADER_SIZE 124
#define CHD_MAP_ENTRY_SIZE 12
#define CHD_MAX_HUNKS 16384
#define CHD_MAX_MAP_BYTES 65536

enum {
    CHD_MAP_CODEC0 = 0,
    CHD_MAP_CODEC1 = 1,
    CHD_MAP_CODEC2 = 2,
    CHD_MAP_CODEC3 = 3,
    CHD_MAP_NONE = 4,
    CHD_MAP_SELF = 5,
    CHD_MAP_PARENT = 6,
    CHD_MAP_RLE_SMALL = 7,
    CHD_MAP_RLE_LARGE = 8,
    CHD_MAP_SELF_0 = 9,
    CHD_MAP_SELF_1 = 10,
    CHD_MAP_PARENT_SELF = 11,
    CHD_MAP_PARENT_0 = 12,
    CHD_MAP_PARENT_1 = 13
};

typedef struct {
    const uint8_t *data;
    uint32_t bytes;
    uint32_t bitpos;
} CHD_BITSTREAM;

typedef struct {
    uint8_t length[16];
    uint16_t code[16];
} CHD_HUFFMAN;

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t be48(const uint8_t *p)
{
    return ((uint64_t)p[0] << 40) | ((uint64_t)p[1] << 32) |
           ((uint64_t)p[2] << 24) | ((uint64_t)p[3] << 16) |
           ((uint64_t)p[4] << 8) | p[5];
}

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static int bit_read(CHD_BITSTREAM *bs, unsigned count, uint32_t *value)
{
    uint32_t v = 0;
    unsigned i;
    if (count > 32 || bs->bitpos > bs->bytes * 8U ||
        count > bs->bytes * 8U - bs->bitpos)
        return -1;
    for (i = 0; i < count; i++) {
        v = (v << 1) |
            ((bs->data[bs->bitpos >> 3] >> (7 - (bs->bitpos & 7))) & 1);
        bs->bitpos++;
    }
    *value = v;
    return 0;
}

static int huffman_read_tree(CHD_BITSTREAM *bs, CHD_HUFFMAN *h)
{
    unsigned n = 0;
    while (n < 16) {
        uint32_t v, run;
        if (bit_read(bs, 4, &v) != 0)
            return -1;
        if (v != 1) {
            h->length[n++] = (uint8_t)v;
            continue;
        }
        if (bit_read(bs, 4, &v) != 0)
            return -1;
        if (v == 1) {
            h->length[n++] = 1;
            continue;
        }
        if (bit_read(bs, 4, &run) != 0)
            return -1;
        run += 3;
        if (run > 16 - n)
            return -1;
        while (run--)
            h->length[n++] = (uint8_t)v;
    }
    return 0;
}

static int huffman_build(CHD_HUFFMAN *h)
{
    uint32_t hist[9] = {0};
    uint32_t start = 0;
    unsigned i, len;
    for (i = 0; i < 16; i++) {
        if (h->length[i] > 8)
            return -1;
        if (h->length[i])
            hist[h->length[i]]++;
    }
    for (len = 8; len > 0; len--) {
        uint32_t sum = start + hist[len];
        uint32_t next = sum >> 1;
        if (len != 1 && (sum & 1))
            return -1;
        hist[len] = start;
        start = next;
    }
    for (i = 0; i < 16; i++)
        h->code[i] = h->length[i] ? (uint16_t)hist[h->length[i]]++ : 0;
    return 0;
}

static int huffman_decode(CHD_BITSTREAM *bs, const CHD_HUFFMAN *h,
                          uint32_t *symbol)
{
    uint32_t code = 0, bit;
    unsigned len, i;
    for (len = 1; len <= 8; len++) {
        if (bit_read(bs, 1, &bit) != 0)
            return -1;
        code = (code << 1) | bit;
        for (i = 0; i < 16; i++) {
            if (h->length[i] == len && h->code[i] == code) {
                *symbol = i;
                return 0;
            }
        }
    }
    return -1;
}

static uint16_t crc16_ccitt(const uint8_t *data, uint32_t size)
{
    uint16_t crc = 0xffff;
    uint32_t i;
    unsigned b;
    for (i = 0; i < size; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (b = 0; b < 8; b++)
            crc = (crc & 0x8000) ?
                (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

static int map_expand(CHD_CTX *ctx, const uint8_t *mapdata,
                      uint32_t mapbytes, uint64_t first_offset,
                      uint16_t expected_crc, uint8_t lengthbits,
                      uint8_t selfbits, uint8_t parentbits)
{
    CHD_BITSTREAM bs;
    CHD_HUFFMAN huff;
    uint8_t *raw;
    uint32_t i, repcount = 0, value;
    uint8_t lastcomp = 0;
    uint32_t last_self = 0;
    uint64_t last_parent = 0, current_offset = first_offset;
    uint32_t rawsize = ctx->hunk_count * CHD_MAP_ENTRY_SIZE;

    if (lengthbits > 32 || selfbits > 32 || parentbits > 32 ||
        mapbytes == 0 || mapbytes > CHD_MAX_MAP_BYTES)
        return CHD_ERR_MAP;

    bs.data = mapdata;
    bs.bytes = mapbytes;
    bs.bitpos = 0;

    if (huffman_read_tree(&bs, &huff) != 0 ||
        huffman_build(&huff) != 0)
        return CHD_ERR_MAP;

    raw = (uint8_t *)malloc(rawsize);
    if (raw == NULL)
        return CHD_ERR_MEMORY;

    /* Decode the compression-type stream, including its RLE symbols. */
    for (i = 0; i < ctx->hunk_count; i++) {
        uint8_t type;
        if (repcount) {
            type = lastcomp;
            repcount--;
        } else {
            if (huffman_decode(&bs, &huff, &value) != 0)
                goto map_error;
            if (value == CHD_MAP_RLE_SMALL) {
                if (huffman_decode(&bs, &huff, &value) != 0)
                    goto map_error;
                type = lastcomp;
                repcount = 2 + value;
            } else if (value == CHD_MAP_RLE_LARGE) {
                uint32_t hi, lo;
                if (huffman_decode(&bs, &huff, &hi) != 0 ||
                    huffman_decode(&bs, &huff, &lo) != 0)
                    goto map_error;
                type = lastcomp;
                repcount = 18 + (hi << 4) + lo;
            } else {
                if (value > CHD_MAP_PARENT_1)
                    goto map_error;
                type = lastcomp = (uint8_t)value;
            }
        }
        raw[i * CHD_MAP_ENTRY_SIZE] = type;
    }
    if (repcount != 0)
        goto map_error;

    /* Decode lengths, offsets and CRCs into the expanded 12-byte map. */
    for (i = 0; i < ctx->hunk_count; i++) {
        uint8_t *entry = raw + i * CHD_MAP_ENTRY_SIZE;
        uint8_t type = entry[0];
        uint64_t offset = current_offset;
        uint32_t length = 0;
        uint16_t crc = 0;

        switch (type) {
        case CHD_MAP_CODEC0:
        case CHD_MAP_CODEC1:
        case CHD_MAP_CODEC2:
        case CHD_MAP_CODEC3:
            if (bit_read(&bs, lengthbits, &length) != 0 ||
                bit_read(&bs, 16, &value) != 0)
                goto map_error;
            crc = (uint16_t)value;
            current_offset += length;
            break;
        case CHD_MAP_NONE:
            length = ctx->hunk_bytes;
            if (bit_read(&bs, 16, &value) != 0)
                goto map_error;
            crc = (uint16_t)value;
            current_offset += length;
            break;
        case CHD_MAP_SELF:
            if (bit_read(&bs, selfbits, &last_self) != 0)
                goto map_error;
            offset = last_self;
            break;
        case CHD_MAP_PARENT:
            if (parentbits == 0 || bit_read(&bs, parentbits, &value) != 0)
                goto map_error;
            offset = value;
            last_parent = offset;
            break;
        case CHD_MAP_SELF_0:
            entry[0] = CHD_MAP_SELF;
            offset = last_self;
            break;
        case CHD_MAP_SELF_1:
            last_self++;
            entry[0] = CHD_MAP_SELF;
            offset = last_self;
            break;
        case CHD_MAP_PARENT_SELF:
            entry[0] = CHD_MAP_PARENT;
            last_parent = ((uint64_t)i * ctx->hunk_bytes) / ctx->unit_bytes;
            offset = last_parent;
            break;
        case CHD_MAP_PARENT_0:
            entry[0] = CHD_MAP_PARENT;
            offset = last_parent;
            break;
        case CHD_MAP_PARENT_1:
            last_parent += ctx->hunk_bytes / ctx->unit_bytes;
            entry[0] = CHD_MAP_PARENT;
            offset = last_parent;
            break;
        default:
            goto map_error;
        }

        entry[1] = (uint8_t)(length >> 16);
        entry[2] = (uint8_t)(length >> 8);
        entry[3] = (uint8_t)length;
        entry[4] = (uint8_t)(offset >> 40);
        entry[5] = (uint8_t)(offset >> 32);
        entry[6] = (uint8_t)(offset >> 24);
        entry[7] = (uint8_t)(offset >> 16);
        entry[8] = (uint8_t)(offset >> 8);
        entry[9] = (uint8_t)offset;
        entry[10] = (uint8_t)(crc >> 8);
        entry[11] = (uint8_t)crc;
    }

    if (crc16_ccitt(raw, rawsize) != expected_crc)
        goto map_error;

    ctx->map = (CHD_MAP_ENTRY *)malloc(ctx->hunk_count * sizeof(CHD_MAP_ENTRY));
    if (ctx->map == NULL) {
        free(raw);
        return CHD_ERR_MEMORY;
    }
    for (i = 0; i < ctx->hunk_count; i++) {
        const uint8_t *entry = raw + i * CHD_MAP_ENTRY_SIZE;
        ctx->map[i].type = entry[0];
        ctx->map[i].length = ((uint32_t)entry[1] << 16) |
                             ((uint32_t)entry[2] << 8) | entry[3];
        ctx->map[i].offset = be48(entry + 4);
        ctx->map[i].crc = be16(entry + 10);
    }
    free(raw);
    return CHD_OK;

map_error:
    free(raw);
    return CHD_ERR_MAP;
}

int chd_v5_open(CHD_CTX *ctx, void *opaque, CHD_READ_FN read_fn,
                uint64_t file_size)
{
    uint8_t header[CHD_V5_HEADER_SIZE];
    uint8_t map_header[16];
    uint8_t *mapdata = NULL;
    uint64_t map_offset;
    uint32_t map_bytes;
    uint16_t map_crc;
    int result;

    if (!ctx || !read_fn || file_size < CHD_V5_HEADER_SIZE)
        return CHD_ERR_ARGUMENT;
    memset(ctx, 0, sizeof(*ctx));
    ctx->opaque = opaque;
    ctx->read = read_fn;
    ctx->file_size = file_size;

    if (read_fn(opaque, 0, header, sizeof(header)) != 0)
        return CHD_ERR_IO;
    if (memcmp(header, "MComprHD", 8) != 0 ||
        be32(header + 8) != CHD_V5_HEADER_SIZE ||
        be32(header + 12) != 5)
        return CHD_ERR_FORMAT;

    ctx->compression[0] = be32(header + 16);
    ctx->compression[1] = be32(header + 20);
    ctx->compression[2] = be32(header + 24);
    ctx->compression[3] = be32(header + 28);
    ctx->logical_bytes = ((uint64_t)be32(header + 32) << 32) |
                         be32(header + 36);
    map_offset = ((uint64_t)be32(header + 40) << 32) |
                 be32(header + 44);
    ctx->hunk_bytes = be32(header + 56);
    ctx->unit_bytes = be32(header + 60);

    if (ctx->hunk_bytes == 0 || ctx->unit_bytes == 0 ||
        ctx->logical_bytes == 0 ||
        (ctx->logical_bytes % ctx->hunk_bytes) != 0 ||
        ctx->logical_bytes / ctx->hunk_bytes > CHD_MAX_HUNKS ||
        map_offset > file_size || file_size - map_offset < 16)
        return CHD_ERR_FORMAT;

    /* This first implementation intentionally rejects parent-dependent CHDs. */
    for (result = 104; result < 124; result++) {
        if (header[result] != 0)
            return CHD_ERR_PARENT;
    }

    ctx->hunk_count = (uint32_t)(ctx->logical_bytes / ctx->hunk_bytes);
    if (read_fn(opaque, map_offset, map_header, sizeof(map_header)) != 0)
        return CHD_ERR_IO;

    map_bytes = be32(map_header);
    map_crc = be16(map_header + 10);
    if (map_bytes == 0 || map_bytes > CHD_MAX_MAP_BYTES ||
        map_offset + 16 > file_size ||
        map_bytes > file_size - (map_offset + 16))
        return CHD_ERR_MAP;

    mapdata = (uint8_t *)malloc(map_bytes);
    if (mapdata == NULL)
        return CHD_ERR_MEMORY;
    if (read_fn(opaque, map_offset + 16, mapdata, map_bytes) != 0) {
        free(mapdata);
        return CHD_ERR_IO;
    }

    result = map_expand(ctx, mapdata, map_bytes, be48(map_header + 4),
                        map_crc, map_header[12], map_header[13],
                        map_header[14]);
    free(mapdata);
    if (result != CHD_OK)
        chd_v5_close(ctx);
    return result;
}

void chd_v5_close(CHD_CTX *ctx)
{
    if (!ctx)
        return;
    if (ctx->map)
        free(ctx->map);
    memset(ctx, 0, sizeof(*ctx));
}

int chd_v5_read_hunk(CHD_CTX *ctx, uint32_t hunk, uint8_t *dest)
{
    CHD_MAP_ENTRY *entry;
    if (!ctx || !ctx->map || !dest || hunk >= ctx->hunk_count)
        return CHD_ERR_ARGUMENT;
    entry = &ctx->map[hunk];

    if (entry->type == CHD_MAP_NONE) {
        if (entry->offset > ctx->file_size ||
            ctx->hunk_bytes > ctx->file_size - entry->offset)
            return CHD_ERR_MAP;
        return ctx->read(ctx->opaque, entry->offset, dest,
                         ctx->hunk_bytes) == 0 ? CHD_OK : CHD_ERR_IO;
    }
    if (entry->type == CHD_MAP_SELF) {
        if (entry->offset >= ctx->hunk_count || entry->offset == hunk)
            return CHD_ERR_MAP;
        return chd_v5_read_hunk(ctx, (uint32_t)entry->offset, dest);
    }

    /* Codec paths are added separately; don't misinterpret compressed data. */
    if (entry->type <= CHD_MAP_CODEC3)
        return CHD_ERR_CODEC;
    if (entry->type == CHD_MAP_PARENT)
        return CHD_ERR_PARENT;
    return CHD_ERR_MAP;
}
