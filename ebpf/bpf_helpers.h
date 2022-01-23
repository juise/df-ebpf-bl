#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#include <linux/bpf.h>

#if defined(DEBUG)
#define bpf_printk(fmt, ...) \
	{ \
		char __fmt[] = fmt; \
                bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
	}
#else
#define bpf_printk(fmt, ...) \
	((void)0)
#endif

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* From tools/lib/bpf/libbpf.h */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

/* helper functions called from eBPF programs written in C */

static void *(*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) =
  	(void *)BPF_FUNC_ringbuf_output;
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;

#endif
