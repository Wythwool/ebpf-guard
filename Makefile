GO=go
BPF_CLANG?=clang
BPF_CFLAGS?=-O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types

BPF_SRCS=$(wildcard bpf/*.bpf.c)
BPF_OBJS=$(patsubst %.bpf.c,build/%.o,$(notdir $(BPF_SRCS)))

all: build $(BPF_OBJS) bin/ebpf-guard

build:
	mkdir -p build bin

build/%.o: bpf/%.bpf.c bpf/common.h bpf/vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I./bpf -c $< -o $@

bin/ebpf-guard: cmd/ebpf-guard/main.go internal/rules/rules.go
	$(GO) mod tidy
	$(GO) build -o bin/ebpf-guard ./cmd/ebpf-guard

clean:
	rm -rf build bin
