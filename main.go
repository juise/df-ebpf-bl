package main

import (
	"os"
	"os/signal"

	"flag"
	"syscall"

	"net"

	"errors"

	"encoding/binary"

	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	log "github.com/sirupsen/logrus"

	"df-ebpf-bl/bl/bitmap"
	//"df-ebpf-bl/bl/supply"
)

const (
	ebpfFS            = "/sys/fs/bpf"
	egressProgName    = "egress"
	blacklistMapName  = "backlist_map"
	ringbufferMapName = "blocked_map"
)

var (
	flagProg = flag.String("prog", "./ebpf/bl.elf", "The llvm/clang compiled binary ELF file")
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})

	if syscall.Geteuid() != 0 {
		log.Info("cannot initialize application, application must run under root or sudo or with SUID bit\n")
		os.Exit(1)
	}

}

func loop(rd *ringbuf.Reader) error {
	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case signal := <-signalChannel:
			switch signal {
			case syscall.SIGINT, syscall.SIGTERM:
				if err := rd.Close(); err != nil {
					log.Errorf("failed to close ringbuffer reader: %s", err)
				}

				log.Info("terminating...")
				return nil
			}
		}
	}
}

func main() {
	log.Info("df-ebpf-bl started")

	// let's pretend the linux kernel version [5.13] check is here

	cgroup, err := os.Open("/sys/fs/cgroup")
	if err != nil {
		log.Errorf("failed to open cgroup: %s", err)
		os.Exit(1)
	}
	defer cgroup.Close()

	flag.Parse()

	collection, err := ebpf.LoadCollection(*flagProg)
	if err != nil {
		log.Errorf("failed to loaf ebpf program: %s", err)
		os.Exit(1)
	}

	//resp, err := supply.Fetch()
	//if err != nil {
	//	log.Errorf("failed to fetch blacklist: %s", err)
	//	os.Exit(1)
	//}

	bmap := bitmap.New()
	//setbit_func := func(i int, j int) {
	//	bitmap.SetBit(bmap, i, j)
	//}

	bitmap.SetBit(bmap, 0, 8)
	bitmap.SetBit(bmap, 1, 8)
	bitmap.SetBit(bmap, 2, 8)
	bitmap.SetBit(bmap, 3, 8)

	//if err = supply.Parse(resp, setbit_func); err != nil {
	//	log.Errorf("failed to parse blacklist: %s", err)
	//	os.Exit(1)
	//}

	var blacklistBitmapMap, ringbufferMap *ebpf.Map
	blockedPinPath := filepath.Join(ebpfFS, blacklistMapName)

	blacklistBitmapMap, _ = collection.Maps[blacklistMapName]
	blacklistBitmapMap.Pin(blockedPinPath)

	for i := 0; i < 32; i++ {
		if err = blacklistBitmapMap.Put(uint32(i), bmap[i]); err != nil {
			log.Errorf("failed to fill blacklist map: %s", err)
			os.Exit(1)
		}
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: collection.Programs[egressProgName],
	})
	if err != nil {
		log.Errorf("failed to attach ebpf to cgroup: %s", err)
		os.Exit(1)

		panic(err)
	}
	defer l.Close()

	ringbufferMap, _ = collection.Maps[ringbufferMapName]
	rd, err := ringbuf.NewReader(ringbufferMap)
	if err != nil {
		log.Errorf("failed to open ringbuffer reader: %s", err)
		os.Exit(1)
	}
	defer rd.Close()

	go loop(rd)

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Errorf("failed to read from ringbuffer: %s", err)
			continue
		}

		source := binary.BigEndian.Uint32(record.RawSample[0:4])
		dest := binary.BigEndian.Uint32(record.RawSample[4:8])
		log.Infof("blocked from %s to %s", intToIP(source).String(), intToIP(dest).String())
	}

	os.Exit(0)
}

func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
