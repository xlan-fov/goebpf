#include "bpf_helpers.h"
#include <arpa/inet.h>
#include "stdlib.h"

#define MAX_RULES  128
#define NANO_TO_SEC 1000000000
#define default_pps 100
#define default_bps 100000


// 以太网头部
struct ethhdr {
  __u8 h_dest[6]; // 目的MAC地址
  __u8 h_source[6]; // 源MAC地址
  __u16 h_proto;  // 协议类型
} __attribute__((packed));  
// 紧凑排列不要对结构体进行内存对齐，以确保结构体的大小与实际以太网头部大小一致。

// IPv4头部
struct iphdr {
  __u8 ihl : 4; // 首部长度，,占4位
  __u8 version : 4; // 版本号，占4位
  __u8 tos; // 服务类型
  __u16 tot_len;  // 总长度
  __u16 id; // 标识
  __u16 frag_off; // 分片偏移
  __u8 ttl; // 生存时间
  __u8 protocol;  // 协议
  __u16 check;  // 校验和
  __u32 saddr;  // 源IP地址
  __u32 daddr;  // 目的IP地址
} __attribute__((packed));  
// 紧凑排列

struct ip_stats{
    __u64 pps;  //每秒数据包数
    __u64 bps;  //每秒字节数
    __u64 next_update;  //下一次更新时间
};

BPF_MAP_DEF(ip_counter) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct ip_stats),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ip_counter);

BPF_MAP_DEF(ip_blacklist_t) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ip_blacklist_t);

BPF_MAP_DEF(ip_blacklist_p) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ip_blacklist_p);

BPF_MAP_DEF(config_pps) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(config_pps);

BPF_MAP_DEF(config_bps) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(config_bps);

BPF_MAP_DEF(block_flag) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(block_flag);

BPF_MAP_DEF(unblock_time) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(unblock_time);

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end; //数据包的结束指针
  void *data = (void *)(long)ctx->data; //数据包的起始指针

  //将数据包的起始指针转换为以太网头部结构体的指针
  struct ethhdr *ether = data;
  //bpf_printk("proto:%x\n",ether->h_proto);
  //以太网头部超出边界说明以太网头部不完整，要丢弃
  if (data + sizeof(*ether) > data_end) { 
    // Malformed Ethernet header
    return XDP_PASS;
  }
  //检查以太网头部的协议字段是否为IPv4协议
  if (ether->h_proto != 0x08U ) {  
    // 非IPv4数据包，直接放行
    //bpf_printk("pass----------non ip packet\n");
    return XDP_DROP;
  }
  struct iphdr *ip=NULL;
  data += sizeof(*ether); //将数据指针移动到IPv4头部
  ip = data;  
  //检查IPv4头部是否超出数据包的边界
  if (data + sizeof(*ip) > data_end) {
    return XDP_DROP;
  }
  __u32 saddr = ip->saddr;
  saddr = htonl(saddr);
  __u64 *blocked_perm = NULL;    // Check ip_blacklist_p
  blocked_perm=bpf_map_lookup_elem(&ip_blacklist_p, &saddr);
  if (blocked_perm) {
    return XDP_DROP;
  }
  __u64 *blocked_temp = NULL;    // Check ip_blacklist_t
  blocked_temp=bpf_map_lookup_elem(&ip_blacklist_t, &saddr);
  struct ip_stats* ip_stats_pointer= NULL;
  ip_stats_pointer=bpf_map_lookup_elem(&ip_counter, &saddr);
  __u64 now = bpf_ktime_get_ns(); //获取当前的内核时间戳(纳秒)
  __u16 pkt_len = data_end - data;
  if (blocked_temp) {
    //bpf_printk("Blocked:%d---------%x\n",saddr,saddr);
    __u32 block_flag_key=3;
    __u32 unblock_time_key=4;
    __u64 *block_flag_value = bpf_map_lookup_elem(&block_flag, &block_flag_key);
    __u64 *unblock_time_value = bpf_map_lookup_elem(&unblock_time, &unblock_time_key);
    if (block_flag_value==NULL || unblock_time_value==NULL) {
      //bpf_printk("block_flag or unblock_time is NULL\n");
      return XDP_DROP;
    }
    if (*block_flag_value>0) {
      //bpf_printk("Blocked forever:%d---------%x\n",saddr,saddr);
      return XDP_DROP;
    }
    if (ip_stats_pointer) {
      if (now - ip_stats_pointer->next_update >= (*unblock_time_value)*NANO_TO_SEC) {
        bpf_map_delete_elem(&ip_blacklist_t, &saddr);
        ip_stats_pointer->pps = 1;
        ip_stats_pointer->bps = pkt_len ;
        ip_stats_pointer->next_update = now + NANO_TO_SEC;
        bpf_map_update_elem(&ip_counter, &saddr, ip_stats_pointer, BPF_ANY);
        return XDP_PASS;
      }
    } else {
      struct ip_stats new_ip_stats={0};
      new_ip_stats.pps = 1;
      new_ip_stats.bps = pkt_len;
      new_ip_stats.next_update = now + NANO_TO_SEC;
      bpf_map_update_elem(&ip_counter, &saddr, &new_ip_stats, BPF_ANY);
    }
    //bpf_printk("Blocked:%d---------%x\n",saddr,saddr);
    return XDP_DROP;
  }
  if (ip_stats_pointer) {
    if (now > ip_stats_pointer->next_update) {
      ip_stats_pointer->pps = 1;
      ip_stats_pointer->bps = pkt_len ;
      ip_stats_pointer->next_update = now + NANO_TO_SEC;
    } else {
      ip_stats_pointer->pps+=1;
      ip_stats_pointer->bps += pkt_len;
    }
    bpf_map_update_elem(&ip_counter, &saddr, ip_stats_pointer, BPF_ANY);
    ip_stats_pointer=bpf_map_lookup_elem(&ip_counter, &saddr);
  } else {
    struct ip_stats new_ip_stats={0};
    new_ip_stats.pps = 1;
    new_ip_stats.bps = pkt_len;
    new_ip_stats.next_update = now + NANO_TO_SEC;
    bpf_map_update_elem(&ip_counter, &saddr, &new_ip_stats, BPF_ANY);
    ip_stats_pointer=bpf_map_lookup_elem(&ip_counter, &saddr);
  }
  if (ip_stats_pointer==NULL) {
    //bpf_printk("pass----------ip_stats\n");
    return XDP_PASS;
  }
  __u32 limit_pps = default_pps;
  __u32 limit_bps = default_bps;
  __u32 pps_key=1;
  __u32 bps_key=2;
  __u64 *pps_value = bpf_map_lookup_elem(&config_pps, &pps_key);
  __u64 *bps_value = bpf_map_lookup_elem(&config_bps, &bps_key);
  if (pps_value) {
    limit_pps = *pps_value;
  }
  if (bps_value) {
    limit_bps = *bps_value;
  }
  if (ip_stats_pointer->pps > limit_pps || ip_stats_pointer->bps > limit_bps) {
    __u32 value=1;
    bpf_map_update_elem(&ip_blacklist_t, &saddr, &value, BPF_ANY);
    return XDP_DROP;
  }
  //bpf_printk("pass----------not limit\n");
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
