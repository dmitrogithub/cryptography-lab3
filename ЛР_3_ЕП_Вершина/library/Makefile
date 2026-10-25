CC ?= cc
AR ?= ar
MODE ?= 1
BUILD_DIR ?= build/mode$(MODE)

CPPFLAGS ?=
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=
LDLIBS ?=

CPPFLAGS += -Iinclude -Ithird_party -Isrc -DDSTU9212_MODE=$(MODE)

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifneq (,$(filter Windows% MINGW% MSYS% CYGWIN%,$(UNAME_S)))
LDLIBS += -lbcrypt
endif

LIB_NAME := libdstu9212.a
LIB_TARGET := $(BUILD_DIR)/$(LIB_NAME)
EXAMPLE_TARGET := $(BUILD_DIR)/dstu9212_example
TEST_VECTORS_TARGET := $(BUILD_DIR)/test_vectors
BENCHMARK_TARGET := $(BUILD_DIR)/benchmark
TEST_VECTORS_OUTPUT ?=
BENCHMARK_ITERATIONS ?= 10

LIB_SRCS := \
	src/api.c \
	src/convert.c \
	src/keygen.c \
	src/ntt_tables.c \
	src/poly.c \
	src/reduce.c \
	src/sign.c \
	src/tables.c \
	src/utils.c \
	third_party/dstu7564/dstu7564.c \
	third_party/dstu8845/dstu8845.c

LIB_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))

TEST_SRCS := \
	tests/test_api.c \
	tests/test_crypto.c \
	tests/test_convert.c \
	tests/test_keygen.c \
	tests/test_keygen_vectors.c \
	tests/test_parameters.c \
	tests/test_poly.c \
	tests/test_reduce.c \
	tests/test_sign.c \
	tests/test_tables.c

TEST_TARGETS := $(patsubst tests/%.c,$(BUILD_DIR)/%,$(TEST_SRCS))
TEST_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(TEST_SRCS))

.PHONY: all lib examples run test benchmark generate-test-vectors clean
.SECONDARY: $(LIB_OBJS) $(TEST_OBJS) $(BUILD_DIR)/examples/main.o \
	$(BUILD_DIR)/tools/benchmark.o $(BUILD_DIR)/tools/test_vectors.o

all: lib examples

lib: $(LIB_TARGET)

examples: $(EXAMPLE_TARGET)

$(LIB_TARGET): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $(LIB_OBJS)

$(EXAMPLE_TARGET): $(BUILD_DIR)/examples/main.o $(LIB_TARGET)
	$(CC) $(LDFLAGS) -o $@ $(BUILD_DIR)/examples/main.o $(LIB_TARGET) $(LDLIBS)

$(TEST_VECTORS_TARGET): $(BUILD_DIR)/tools/test_vectors.o $(LIB_TARGET)
	$(CC) $(LDFLAGS) -o $@ $(BUILD_DIR)/tools/test_vectors.o $(LIB_TARGET) $(LDLIBS)

$(BENCHMARK_TARGET): $(BUILD_DIR)/tools/benchmark.o $(LIB_TARGET)
	$(CC) $(LDFLAGS) -o $@ $(BUILD_DIR)/tools/benchmark.o $(LIB_TARGET) $(LDLIBS)

$(BUILD_DIR)/test_%: $(BUILD_DIR)/tests/test_%.o $(LIB_TARGET)
	$(CC) $(LDFLAGS) -o $@ $< $(LIB_TARGET) $(LDLIBS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

run: $(EXAMPLE_TARGET)
	./$(EXAMPLE_TARGET)

test: $(TEST_TARGETS)
	@for test_bin in $(TEST_TARGETS); do \
		echo "./$$test_bin"; \
		./$$test_bin || exit $$?; \
	done

benchmark: $(BENCHMARK_TARGET)
	./$(BENCHMARK_TARGET) $(BENCHMARK_ITERATIONS)

generate-test-vectors: $(TEST_VECTORS_TARGET)
	./$(TEST_VECTORS_TARGET) $(TEST_VECTORS_OUTPUT)

clean:
	$(RM) -r build
