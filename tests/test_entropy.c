#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "entropy.h"

static int near(double a, double b) { return fabs(a - b) < 1e-9; }

static void test_known_values(void)
{
    assert(near(shannon_entropy((const unsigned char *)"", 0), 0.0));
    unsigned char same[1000];
    memset(same, 'A', sizeof same);
    assert(near(shannon_entropy(same, sizeof same), 0.0));
    unsigned char two[1000];
    for (size_t i = 0; i < sizeof two; i++) two[i] = (unsigned char)(i % 2 ? 'a' : 'b');
    assert(near(shannon_entropy(two, sizeof two), 1.0));
    unsigned char all[256 * 4];
    for (size_t i = 0; i < sizeof all; i++) all[i] = (unsigned char)(i % 256);
    assert(near(shannon_entropy(all, sizeof all), 8.0));
}

static void test_classification(void)
{
    assert(classify(0.0) == KIND_EMPTY);
    assert(classify(4.2) == KIND_TEXT);
    assert(classify(6.0) == KIND_CODE_OR_DATA);
    assert(classify(7.2) == KIND_COMPRESSED_OR_PACKED);
    assert(classify(7.99) == KIND_ENCRYPTED_OR_RANDOM);
    assert(strcmp(kind_name(KIND_TEXT), "text or structured data") == 0);
}

static void test_english_text_is_low(void)
{
    const char *s = "The quick brown fox jumps over the lazy dog while the cat watches from the window sill.";
    double e = shannon_entropy((const unsigned char *)s, strlen(s));
    assert(e > 3.0 && e < 5.0);
}

static void test_formats(void)
{
    assert(strcmp(detect_format((const unsigned char *)"\x7f""ELF\2\1\1", 7), "ELF executable") == 0);
    assert(strcmp(detect_format((const unsigned char *)"MZ\x90\x00", 4), "PE/DOS executable (MZ)") == 0);
    assert(strcmp(detect_format((const unsigned char *)"PK\x03\x04xx", 6), "ZIP archive") == 0);
    assert(strcmp(detect_format((const unsigned char *)"\x1f\x8b\x08", 3), "gzip") == 0);
    assert(detect_format((const unsigned char *)"hello", 5) == NULL);
    assert(detect_format((const unsigned char *)"M", 1) == NULL);      /* too short must not over-read */
    assert(detect_format((const unsigned char *)"", 0) == NULL);
}

static void test_block_count(void)
{
    assert(block_count(0, 4096) == 0);
    assert(block_count(4096, 4096) == 1);
    assert(block_count(4097, 4096) == 2);
    assert(block_count(100, 0) == 0);
}

int main(void)
{
    test_known_values();
    test_classification();
    test_english_text_is_low();
    test_formats();
    test_block_count();
    puts("all tests passed");
    return 0;
}
