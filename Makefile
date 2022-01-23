
.PHONY: all
all: build_ebpf build

.PHONY: build_ebpf
build_ebpf:
	$(MAKE) -C ebpf

.PHONY: build
build:
	go build -o df-ebpf-bl
