#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "entropy.h"

#define MAX_FILE (256UL * 1024UL * 1024UL)

static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "entropy: %s: %s\n", path, strerror(errno)); return NULL; }
    size_t cap = 1 << 16, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) { fclose(f); return NULL; }
    for (;;) {
        if (len == cap) {
            if (cap >= MAX_FILE) { fprintf(stderr, "entropy: %s: larger than %lu MiB, refusing\n", path, MAX_FILE >> 20); free(buf); fclose(f); return NULL; }
            cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb) { free(buf); fclose(f); return NULL; }
            buf = nb;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        if (n == 0) break;
        len += n;
    }
    fclose(f);
    *out_len = len;
    return buf;
}

static void usage(void)
{
    fputs("usage: entropy [-b blocksize] [-t threshold] <file>\n"
          "  -b  block size in bytes for the profile (default 4096, 0 = summary only)\n"
          "  -t  report blocks at or above this bits/byte (default 7.5)\n"
          "exit code 3 when the whole file looks encrypted or random\n", stderr);
}

int main(int argc, char **argv)
{
    size_t block = 4096;
    double threshold = 7.5;
    const char *path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            char *end; unsigned long v = strtoul(argv[++i], &end, 10);
            if (*end || v > (1UL << 24)) { usage(); return 2; }
            block = (size_t)v;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            char *end; threshold = strtod(argv[++i], &end);
            if (*end || threshold < 0.0 || threshold > 8.0) { usage(); return 2; }
        } else if (argv[i][0] != '-' && !path) {
            path = argv[i];
        } else { usage(); return 2; }
    }
    if (!path) { usage(); return 2; }

    size_t len = 0;
    unsigned char *buf = read_file(path, &len);
    if (!buf) return 2;

    double total = shannon_entropy(buf, len);
    entropy_kind kind = classify(total);
    const char *fmt = detect_format(buf, len);
    printf("file:    %s\nsize:    %zu bytes\nformat:  %s\nentropy: %.4f bits/byte\nverdict: %s\n",
           path, len, fmt ? fmt : "unknown", total, kind_name(kind));

    if (block > 0 && len > 0) {
        size_t n = block_count(len, block), hot = 0;
        for (size_t i = 0; i < n; i++) {
            size_t off = i * block, sz = len - off < block ? len - off : block;
            double e = shannon_entropy(buf + off, sz);
            if (e >= threshold) {
                if (hot < 20) printf("  high entropy: offset 0x%zx (%zu bytes) %.4f\n", off, sz, e);
                hot++;
            }
        }
        printf("blocks:  %zu of %zu at or above %.2f bits/byte%s\n", hot, n, threshold, hot > 20 ? " (first 20 shown)" : "");
    }
    free(buf);
    return kind == KIND_ENCRYPTED_OR_RANDOM ? 3 : 0;
}
