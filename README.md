# df-ebpf-bl

## Requirements
- linux kernel 5.13
- golang 1.17
- llvm/clang 13

## Build

to build all:
```sh
make
```
to build user-space part:
```
make build
```
to build kernel-space part:
```
make build_ebpf
```
