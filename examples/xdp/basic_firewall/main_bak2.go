package main2

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/dropbox/goebpf"
)

type ipAddressList []string

type Config struct {
	InterfaceName string
	PPS           uint64
	BPS           uint64
	Ipv4Blacklist []string
	//Ipv6Blacklist []string
	BlockTime   uint64
	UnBlockTime uint64
}

// 编译好的eBPF程序路径
var elf = flag.String("elf", "ebpf_prog/xdp_fw.elf", "clang/llvm compiled binary file")

// 存储要阻止的IPv4地址
var ipList ipAddressList

const config_path = "./xdpfw.json"

func main() {
	configFile, err1 := os.Open(config_path)
	if err1 != nil {
		fatalError("Failed to open config file: %v", err1)
	}
	defer configFile.Close()

	configData, err2 := io.ReadAll(configFile)
	if err2 != nil {
		fatalError("Failed to read config file: %v", err2)
	}
	var config Config
	err3 := json.Unmarshal(configData, &config)
	if err3 != nil {
		fatalError("Failed to unmarshal config: %v", err3)
	}
	log.Printf("InterfaceName: %s", config.InterfaceName)
	log.Printf("PPS: %d", config.PPS)
	log.Printf("BPS: %d", config.BPS)
	log.Printf("Ipv4Blacklist: %v", config.Ipv4Blacklist)
	log.Printf("BlockTime: %d", config.BlockTime)
	log.Printf("UnBlockTime: %d", config.UnBlockTime)
	//log.Printf("Ipv6Blacklist: %v", config.Ipv6Blacklist)
	//创建eBPF系统实例，并加载编译好的eBPF程序。
	bpf := goebpf.NewDefaultEbpfSystem()
	err4 := bpf.LoadElf(*elf)
	if err4 != nil {
		fatalError("LoadElf() failed: %v", err4)
	}
	printBpfInfo(bpf)
	config_pps := bpf.GetMapByName("config_pps")
	config_bps := bpf.GetMapByName("config_bps")
	if config_pps == nil {
		fatalError("eBPF map 'config_pps' not found")
	} else {
		err := config_pps.Insert(1, config.PPS)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	if config_bps == nil {
		fatalError("eBPF map 'config_bps' not found")
	} else {
		err := config_bps.Insert(2, config.BPS)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	block_time := bpf.GetMapByName("block_time")
	un_block_time := bpf.GetMapByName("unblock_time")
	if block_time == nil {
		fatalError("eBPF map 'block_time' not found")
	} else {
		err := block_time.Insert(3, config.BlockTime)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	if un_block_time == nil {
		fatalError("eBPF map 'un_block_time' not found")
	} else {
		err := un_block_time.Insert(4, config.UnBlockTime)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	ip_blacklist := bpf.GetMapByName("ip_blacklist")
	if ip_blacklist == nil {
		fatalError("eBPF map 'ip_blacklist' not found")
	}
	ipv6_blacklist := bpf.GetMapByName("ipv6_blacklist")
	if ipv6_blacklist == nil {
		fatalError("eBPF map 'ipv6_blacklist' not found")
	}
	for i, s := range config.Ipv4Blacklist {
		ipu32, erri := ipToUint32(s)
		if erri != nil {
			fmt.Println(erri)
			continue
		}
		err := ip_blacklist.Insert(ipu32, 1)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
		ipList = append(ipList, s)
		fmt.Printf("Ipv4Blacklist[%d]: %d----%x\n", i, ipu32, ipu32)
	}
	fmt.Println("\nIPv4 黑名单列表：")
	var currentKey interface{}

	// 获取第一个键
	firstKey, err5 := ip_blacklist.GetNextKey(nil)
	if err5 != nil {
		// 处理错误，可能是 Map 为空
		fmt.Printf("Error getting first key:%v", err5)
		return
	}
	currentKey = firstKey

	// 循环直到没有更多的键
	for currentKey != nil {
		// 使用当前键获取下一个键
		nextKey, err_1 := ip_blacklist.GetNextKey(currentKey)

		// 打印或处理键和值
		currentValue, err := ip_blacklist.Lookup(currentKey)
		if err != nil {
			fmt.Println("Error looking up value for key:", err)
		} else {
			fmt.Println("Key:", currentKey, "Value:", currentValue)
		}
		if err_1 != nil {
			//fmt.Println("Error getting next key:", err_1)
			break
		}
		// 更新当前键为下一个键，继续遍历
		currentKey = nextKey
	}
	// Get XDP program. Name simply matches function from xdp_fw.c:
	//      int firewall(struct xdp_md *ctx) {
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		fatalError("Program 'firewall' not found.")
	}

	// Populate eBPF map with IPv4 addresses to block
	fmt.Println("Blacklisting IPv4 or IPv6 addresses...")

	// Load XDP program into kernel
	err6 := xdp.Load()
	if err6 != nil {
		fatalError("xdp.Load(): %v", err6)
	}

	// Attach to interface
	err7 := xdp.Attach(config.InterfaceName)
	if err7 != nil {
		fatalError("xdp.Attach(): %v", err7)
	}
	//用于确保在函数返回之前调用xdp.Detach函数
	defer xdp.Detach()

	//当用户按下Ctrl+C时，程序不会立即终止，而是将中断信号发送到ctrlC通道。
	//程序可以在适当的时候检查这个通道，以确定是否接收到了中断信号，
	//并据此执行正常退出操作。
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	fmt.Println("XDP program successfully loaded and attached.")
	fmt.Println("Press CTRL+C to stop.")
	fmt.Println()

	//创建一个定时器，每秒触发一次。
	//进入一个无限循环，同时等待定时器通道和中断信号通道。
	//当定时器通道接收到信号时，打印IP地址和DROP计数。
	//当中断信号通道接收到信号时，打印退出消息并退出程序。
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			/*
				fmt.Println("IP/IPV6                 DROPs")

				for i := 0; i < len(ipList); i++ {
					fmt.Printf("%s\n", ipList[i])
				}
				fmt.Println()
			*/

		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}

}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// Implements flag.Value
func (i *ipAddressList) String() string {
	return fmt.Sprintf("%+v", *i)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

func ipToUint32(ip string) (uint32, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return 0, fmt.Errorf(ip + "无效的IP地址")
	}
	ipv4 := addr.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf(ip + "不是IPv4地址")
	}
	return uint32(ipv4[0])<<24 + uint32(ipv4[1])<<16 + uint32(ipv4[2])<<8 + uint32(ipv4[3]), nil
}
