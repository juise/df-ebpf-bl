#include <linux/types.h>

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

#include "bpf_helpers.h"


struct bpf_map_def SEC("maps") backlist_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 32,
};

struct bpf_map_def SEC("maps") blocked_map = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 24,
};

static __always_inline int is_bit_present(int octet, int i) {
    // each octet is built on top of 8 uint32's
    __u32 key = (8 * octet) + (i / 32);

    __u32 *value = bpf_map_lookup_elem(&backlist_map, &key);

    if (!value) {
        bpf_printk("check octect %d bit %d, failed, treat bit is absent", octet, i);
        return 0;
    }

    if ((*value & (1 << (i % 32))) > 0) {
	    bpf_printk("check octect %d bit %d, against value %d, bit is present", octet, i, *value);
	    return 1;
    } else {
	    bpf_printk("check octect %d bit %d, against value %d, bit is absent", octet, i, *value);
	    return 0;
    }
}

static __always_inline int is_all_bits_present(__be32 addr) {
    int i;
    #pragma clang loop unroll(full)
    for (int octet = 3; octet >= 0; octet--) {
	    i = (addr >> (24 - (octet * 8))) & 0xFF;
	    if (!is_bit_present(3 - octet, i)) {
            return 0;
        }
    }
    return 1;
}

static __always_inline int is_allowed(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;

    if ((void *)ip + sizeof(*ip) > data_end) {
        return 1;
    }

	if (is_all_bits_present(ip->daddr)) {
		unsigned char saddr[4];
		saddr[0] = ip->saddr & 0xFF;
		saddr[1] = (ip->saddr >> 8) & 0xFF;
		saddr[2] = (ip->saddr >> 16) & 0xFF;
		saddr[3] = (ip->saddr >> 24) & 0xFF;
		unsigned char daddr[4];
		daddr[0] = ip->daddr & 0xFF;
		daddr[1] = (ip->daddr >> 8) & 0xFF;
		daddr[2] = (ip->daddr >> 16) & 0xFF;
		daddr[3] = (ip->daddr >> 24) & 0xFF;
		bpf_printk("%pI4 -> %pI4 blocked", saddr, daddr);

		__u64 event = (__u64)ip->daddr << 32 | ip->saddr;
		bpf_ringbuf_output(&blocked_map, &event, sizeof(__u64), 0); 

		return 0;
	}
	return 1;
}

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
	if (skb->protocol == __constant_htons(ETH_P_IP)) {
		return is_allowed(skb);
	}
    return 1;
}

char __license[] SEC("license") = "GPL";
