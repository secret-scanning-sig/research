.PHONY: all, clean, build

CFLAGS := -fPIC $(shell pkg-config python libhs --cflags)
LDFLAGS := -lhs $(shell python3-config --ldflags)

all: clean build

build: sssig_rules/hscheck.so
	uv sync

clean:
	find . -name '*.so' -delete
	find . -name '*.o' -delete
	rm -rf .venv

sssig_rules/hscheck.so: sssig_rules/hscheck.o
	$(CC) $(LDFLAGS) -shared -o $@ sssig_rules/hscheck.o
