#ifndef ENTROPY_H
#define ENTROPY_H

#include <stddef.h>

typedef enum { KIND_EMPTY, KIND_TEXT, KIND_CODE_OR_DATA, KIND_COMPRESSED_OR_PACKED, KIND_ENCRYPTED_OR_RANDOM } entropy_kind;

/* Shannon entropy in bits per byte, range 0.0 .. 8.0. */
double shannon_entropy(const unsigned char *buf, size_t len);

/* Heuristic classification of a block from its entropy. */
entropy_kind classify(double bits_per_byte);
const char *kind_name(entropy_kind k);

/* Identify common executable and archive formats from magic bytes; returns NULL when unknown. */
const char *detect_format(const unsigned char *buf, size_t len);

/* Number of blocks of block_size covering len bytes (last one may be shorter). Returns 0 if block_size is 0. */
size_t block_count(size_t len, size_t block_size);

#endif
