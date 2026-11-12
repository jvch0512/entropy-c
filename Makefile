CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror
BUILD := build

all: $(BUILD)/entropy

$(BUILD)/entropy: src/main.c src/entropy.c src/entropy.h | $(BUILD)
	$(CC) $(CFLAGS) src/main.c src/entropy.c -o $@ -lm

$(BUILD)/test_entropy: tests/test_entropy.c src/entropy.c src/entropy.h | $(BUILD)
	$(CC) $(CFLAGS) -fsanitize=address,undefined tests/test_entropy.c src/entropy.c -Isrc -o $@ -lm

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_entropy
	./$(BUILD)/test_entropy

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
