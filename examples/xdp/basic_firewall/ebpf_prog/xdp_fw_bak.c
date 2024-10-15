#include "bpf_helpers.h"
#include "stdlib.h"
#include "stdatomic.h"

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

typedef __u8 __u128[16];

struct ipv6hdr {
  __u8 version : 4;  // 版本号，占4位
  __u8 traffic_class : 8;  // 流量类别，占8位
  __u32 flow_label : 20;  // 流标签，占20位
  __u16 payload_len;  // 有效载荷长度
  __u8 next_hdr;  // 下一个头部
  __u8 hop_limit;  // 跳数限制
  __u128 saddr;  // 源地址  
  __u128 daddr;  // 目的地址
} __attribute__((packed));



// TCP header
struct tcphdr {
  __u16 source;
  __u16 dest;
  __u32 seq;
  __u32 ack_seq;
  union {
    struct {
      // 字段顺序已转换为LittleEndian -> BigEndian
      // 为了简化标志检查（无需ntohs()）
      __u16 ns : 1,
      reserved : 3,
      doff : 4,
      fin : 1,
      syn : 1,
      rst : 1,
      psh : 1,
      ack : 1,
      urg : 1,
      ece : 1,
      cwr : 1;
    };
  };
  __u16 window;
  __u16 check;
  __u16 urg_ptr;
};

// UDP header
struct udphdr {
  __u16 source;
  __u16 dest;
  __u16 len;
  __u16 check;
} __attribute__((packed));

// ICMP header
struct icmphdr {
  __u8 type;
  __u8 code;
  __u16 checksum;
  union {
    struct {
      __u16 id; 
      __u16 sequence;
    } echo;
    __u32 gateway;
    struct {
      __u16 __unused;
      __u16 mtu;
    } frag;
  } un;
};  


BPF_MAP_DEF(matches) = { //定义映射类型,为系统中的每个CPU提供一个独立的数组实例
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,  
    .key_size = sizeof(__u32),  //定义键的大小
    .value_size = sizeof(__u64),  //定义值的大小
    .max_entries = MAX_RULES, //定义最大条目数
};
BPF_MAP_ADD(matches); //将映射添加到BPF程序中


BPF_MAP_DEF(blacklist) = { //最长前缀匹配（LPM）树映射，用于IP地址的快速查找
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),  //定义键的大小
    .value_size = sizeof(__u32),  //定义值的大小
    .max_entries = MAX_RULES, //定义最大条目数
};
BPF_MAP_ADD(blacklist); //将映射添加到BPF程序中

struct ip_stats{
    _Atomic __u64 pps;  //每秒数据包数
    _Atomic __u64 bps;  //每秒字节数
    __u64 next_update;  //下一次更新时间
};

BPF_MAP_DEF(ip_counter) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct ip_stats),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ip_counter);

BPF_MAP_DEF(ip_blacklist) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ip_blacklist);

BPF_MAP_DEF(ipv6_counter) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u128),
    .value_size = sizeof(struct ip_stats),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ipv6_counter);

BPF_MAP_DEF(ipv6_blacklist) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u128),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(ipv6_blacklist);

// eBPF map to store IP proto counters (tcp, udp, etc)
BPF_MAP_DEF(protocols) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(protocols);

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end; //数据包的结束指针
  void *data = (void *)(long)ctx->data; //数据包的起始指针

  //将数据包的起始指针转换为以太网头部结构体的指针
  struct ethhdr *ether = data;
  //以太网头部超出边界说明以太网头部不完整，要丢弃
  if (data + sizeof(*ether) > data_end) { 
    // Malformed Ethernet header
    return XDP_ABORTED;
  }
  //检查以太网头部的协议字段是否为IPv4或IPv6协议
  if (ether->h_proto != 0x08U || ether->h_proto != 0xDD86U) {  // htons(ETH_P_IP) -> 0x08U, htons(ETH_P_IPV6) -> 0xDD86U
    // 非IPv4或IPv6数据包，直接放行
    return XDP_PASS;
  }
  struct iphdr *ip=NULL;
  struct ipv6hdr *ipv6=NULL;
  struct ip_stats* ip_stats_pointer= NULL;
  __u64 *blocked = NULL;    // Check blacklist map.
  if (ether->h_proto == 0x08U) {
    // IPv4数据包
    data += sizeof(*ether); //将数据指针移动到IPv4头部
    ip = data;  
  //检查IPv4头部是否超出数据包的边界
    if (data + sizeof(*ip) > data_end) {
      return XDP_ABORTED;
    }
    blocked=bpf_map_lookup_elem(&ip_blacklist, &ip->saddr);
    ip_stats_pointer=bpf_map_lookup_elem(&ip_counter, &ip->saddr);
  } else {
    // IPv6数据包
    data += sizeof(*ether); //将数据指针移动到IPv6头部
    ipv6 = data;  
    //检查IPv6头部是否超出数据包的边界
    if (data + sizeof(*ipv6) > data_end) {
      return XDP_ABORTED;
    }
    blocked=bpf_map_lookup_elem(&ipv6_blacklist, &ipv6->saddr);
    ip_stats_pointer=bpf_map_lookup_elem(&ipv6_counter, &ipv6->saddr);
  }
  if (blocked) {
    printf("Blocked:%x\n",ip->saddr);
    return XDP_DROP;
  }
  __u64 now = bpf_ktime_get_ns(); //获取当前的内核时间戳(纳秒)
  __u16 pkt_len = data_end - data;
  if (ip_stats_pointer) {
    if (now > ip_stats_pointer->next_update) {
      ip_stats_pointer->pps = 1;
      ip_stats_pointer->bps = pkt_len ;
      ip_stats_pointer->next_update = now + NANO_TO_SEC;
    } else {
      //ip_stats_pointer->pps+=1;
      //ip_stats_pointer->bps += pkt_len;
      atomic_fetch_add(&ip_stats_pointer->pps, 1);
      atomic_fetch_add(&ip_stats_pointer->bps, pkt_len);
    }
  } else {
    struct ip_stats new_ip_stats={0};
    new_ip_stats.pps = 1;
    new_ip_stats.bps = pkt_len;
    new_ip_stats.next_update = now + NANO_TO_SEC;
    if (ether->h_proto == 0x08U) {
      bpf_map_update_elem(&ip_counter, &ip->saddr, &new_ip_stats, BPF_ANY);
    } else {
      bpf_map_update_elem(&ipv6_counter, &ipv6->saddr, &new_ip_stats, BPF_ANY);
    }
  }
  __u32 limit_pps = default_pps;
  __u32 limit_bps = default_bps;
  if (ip_stats_pointer->pps > limit_pps || ip_stats_pointer->bps > limit_bps) {
    __u32 value=1;
    if(ip) {
      bpf_map_update_elem(&ip_blacklist, &ip->saddr, &value, BPF_ANY);
    } else if (ipv6) {
      bpf_map_update_elem(&ipv6_blacklist, &ipv6->saddr, &value, BPF_ANY);
    }
    return XDP_DROP;
  }
  return XDP_PASS;
  //udp

  //syn

  //icmp

  /*
  struct {
    __u32 prefixlen;  //前缀长度
    __u32 saddr;  //源IP地址
  } key;  //存储最长前缀匹配的键

  key.prefixlen = 32;
  key.saddr = ip->saddr;

  // 在黑名单中查找源IP地址
  __u64 *rule_idx = bpf_map_lookup_elem(&blacklist, &key);
  if (rule_idx) {
    // 将rule_idx转换为u32类型
    __u32 index = *(__u32*)rule_idx;    
    // 在matches映射中查找index对应的计数器
    __u64 *counter = bpf_map_lookup_elem(&matches, &index);
    if (counter) {
      (*counter)++;
    }
    return XDP_DROP;
  }
  */
}

char _license[] SEC("license") = "GPL";
