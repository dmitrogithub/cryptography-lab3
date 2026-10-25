CC ?= cc
MODE ?= 1
PYTHON ?= python3
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CPPFLAGS += -Ilibrary/include -Ilibrary/third_party -DDSTU9212_MODE=$(MODE)
LDLIBS ?=
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifneq (,$(filter Windows% MINGW% MSYS% CYGWIN%,$(UNAME_S)))
LDLIBS += -lbcrypt
STUDENT_LDFLAGS += -municode
endif
OUT = build/mode$(MODE)
LIB = library/build/mode$(MODE)/libdstu9212.a
.PHONY: all library demo student clean
all: demo student
library:
	$(MAKE) -C library MODE=$(MODE) CC="$(CC)" CFLAGS="$(CFLAGS)" lib
demo: library
	@mkdir -p $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) examples/demo.c $(LIB) $(LDFLAGS) $(LDLIBS) -o $(OUT)/demo
student: library
	@mkdir -p $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) student/main.c $(LIB) $(LDFLAGS) $(STUDENT_LDFLAGS) $(LDLIBS) -o $(OUT)/lab3
clean:
	$(RM) -r build
	$(MAKE) -C library clean
