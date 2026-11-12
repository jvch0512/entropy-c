#include "entropy.h"

#include <math.h>
#include <string.h>

double shannon_entropy(const unsigned char *buf, size_t len)
{
    if (len == 0) return 0.0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) counts[buf[i]]++;
    double h = 0.0;
    for (int b = 0; b < 256; b++) {
        if (counts[b] == 0) continue;
        double p = (double)counts[b] / (double)len;
        h -= p * log2(p);
    }
    return h;
}

entropy_kind classify(double e)
{
    if (e < 0.0001) return KIND_EMPTY;
    if (e < 5.0) return KIND_TEXT;
    if (e < 6.8) return KIND_CODE_OR_DATA;
    if (e < 7.5) return KIND_COMPRESSED_OR_PACKED;
    return KIND_ENCRYPTED_OR_RANDOM;
}

const char *kind_name(entropy_kind k)
{
    switch (k) {
    case KIND_EMPTY: return "empty or constant";
    case KIND_TEXT: return "text or structured data";
    case KIND_CODE_OR_DATA: return "native code or mixed data";
    case KIND_COMPRESSED_OR_PACKED: return "compressed or packed";
    case KIND_ENCRYPTED_OR_RANDOM: return "encrypted or random";
    }
    return "unknown";
}

const char *detect_format(const unsigned char *b, size_t n)
{
    if (n >= 4 && memcmp(b, "\x7f""ELF", 4) == 0) return "ELF executable";
    if (n >= 2 && b[0] == 'M' && b[1] == 'Z') return "PE/DOS executable (MZ)";
    if (n >= 4 && (memcmp(b, "\xcf\xfa\xed\xfe", 4) == 0 || memcmp(b, "\xca\xfe\xba\xbe", 4) == 0)) return "Mach-O binary";
    if (n >= 4 && memcmp(b, "PK\x03\x04", 4) == 0) return "ZIP archive";
    if (n >= 2 && b[0] == 0x1f && b[1] == 0x8b) return "gzip";
    if (n >= 6 && memcmp(b, "7z\xbc\xaf\x27\x1c", 6) == 0) return "7-Zip";
    if (n >= 3 && memcmp(b, "BZh", 3) == 0) return "bzip2";
    if (n >= 4 && memcmp(b, "%PDF", 4) == 0) return "PDF";
    if (n >= 4 && memcmp(b, "\x89PNG", 4) == 0) return "PNG";
    return NULL;
}

size_t block_count(size_t len, size_t block_size)
{
    if (block_size == 0) return 0;
    return len / block_size + (len % block_size != 0);
}
