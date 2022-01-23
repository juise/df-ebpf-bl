CLANG := clang-13
LLC   := llc-13

EBPF_SOURCE := bl.c
EBPF_BITCODE := bl.ll
EBPF_BINARY := bl.elf

KERNEL_VERSION = 5.13

KERNEL_INCLUDES = linux-headers/include

all: linux-headers build

build: $(EBPF_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) -c -O2 -g -emit-llvm -target bpf -Rpass-missed=inline -mllvm -inlinehint-threshold=1000 -W -Wall -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types -o $(@:.elf=.ll) -I$(KERNEL_INCLUDES) $<
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o $@ $(@:.elf=.ll)
	$(CLANG) -DDEBUG -c -O2 -g -emit-llvm -target bpf -Rpass-missed=inline -mllvm -inlinehint-threshold=1000 -W -Wall -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types -o $(@:.elf=.ll) -I$(KERNEL_INCLUDES) $<
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o debug_$@ $(@:.elf=.ll)

linux-headers:
	# https://www.kernel.org/doc/Documentation/kbuild/headers_install.txt
	curl https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-$(KERNEL_VERSION).tar.xz | tar xaJ
	$(MAKE) -C linux-$(KERNEL_VERSION) headers_install ARCH=i386 INSTALL_HDR_PATH=$(CURDIR)/linux-headers
	rm -rf linux-$(KERNEL_VERSION)

.PHONY: clean
clean:
	rm -rf $(EBPF_BITCODE) $(EBPF_BINARY) debug_$(EBPF_BINARY)
