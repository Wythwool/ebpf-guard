GO=go
BPF_CLANG?=clang
BPF_CFLAGS?=-O2 -g -target bpf -Wall -Werror -D__TARGET_ARCH_x86
BPF_SRCS=$(wildcard bpf/*.bpf.c)
BPF_OBJS=$(patsubst bpf/%.bpf.c,build/%.o,$(BPF_SRCS))

all: bpf bin/ebpf-guard

bpf: bpf/vmlinux.h $(BPF_OBJS)

bpf/vmlinux.h:
	./scripts/gen_vmlinux.sh

build/%.o: bpf/%.bpf.c bpf/common.h bpf/vmlinux.h
	mkdir -p build bin
	$(BPF_CLANG) $(BPF_CFLAGS) -I./bpf -c $< -o $@

bin/ebpf-guard: cmd/ebpf-guard/main.go internal/rules/rules.go
	$(GO) mod tidy
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$$(git rev-parse --short HEAD 2>/dev/null || echo dev)" -o bin/ebpf-guard ./cmd/ebpf-guard

run:
	sudo -E ./bin/ebpf-guard -prom -json -rules ./configs/rules.sample.yaml

test:
	go test ./internal/

clean:
	rm -rf build bin

.PHONY: all bpf run test clean
