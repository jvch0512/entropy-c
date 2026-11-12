# entropy-c

Small C11 tool that measures **Shannon entropy** of a file, overall and per block, to spot packed, compressed or encrypted content. A classic first-pass triage step in malware analysis and forensics: normal text sits around 4 bits/byte, native code around 6, and compressed or encrypted data approaches 8.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Build and run

```bash
make test all
./build/entropy suspicious.bin
./build/entropy -b 512 -t 7.2 firmware.img    # 512-byte blocks, flag blocks >= 7.2
```

```
file:    suspicious.bin
size:    184320 bytes
format:  PE/DOS executable (MZ)
entropy: 7.6120 bits/byte
verdict: encrypted or random
  high entropy: offset 0x4000 (4096 bytes) 7.9531
blocks:  38 of 45 at or above 7.50 bits/byte
```

(Illustrative output.) Exit code `3` means the whole file looks encrypted or random, so it can gate a pipeline.

## Interpreting results

| bits/byte | Typical content |
|-----------|-----------------|
| < 5.0 | text, source code, structured data |
| 5.0 - 6.8 | native code, mixed data |
| 6.8 - 7.5 | compressed or packed |
| > 7.5 | encrypted, random, or already-compressed media |

Entropy is a hint, not proof: JPEG, MP4 and ZIP files are legitimately high entropy. A normal-looking executable with one very high block, or an executable with a high overall score, deserves a closer look.

## Engineering notes

* Compiled with `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror`
* Tests run under AddressSanitizer and UndefinedBehaviorSanitizer
* File reads grow geometrically and refuse inputs over 256 MiB; magic-byte checks never read past the buffer (tested with truncated inputs)
* No dependencies beyond libc and libm

MIT licensed.
