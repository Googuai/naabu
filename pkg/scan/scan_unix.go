package scan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/projectdiscovery/freeport"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	iputil "github.com/projectdiscovery/utils/ip"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ========== 新增/调整核心常量（解决协程数/超时问题） ==========
const (
	packetSendSize     = 10000
	chanSize           = 10000
	maxRetries         = 3
	sendDelayMsec      = 1
	snaplen            = 1500
	readTimeoutMs      = 500  // pcap阻塞超时：500ms（平衡CPU和响应速度）
	readSleepMs        = 10   // 非阻塞读休眠时间：10ms
	ProtocolICMP       = 1    // ICMP协议号
	ProtocolIPv6ICMP   = 58   // IPv6 ICMP协议号
)

// 协程数 = CPU核心数（避免过度切换）
var NumberOfHandlers = runtime.NumCPU()

// ========== 原有全局变量保留 ==========
var (
	handlers      *Handlers
	icmpConn4     *icmp.PacketConn
	icmpConn6     *icmp.PacketConn
	transportPacketSend chan *PkgSend
	icmpPacketSend      chan *PkgSend
	ethernetPacketSend  chan *PkgSend
	ListenHandlers      []*ListenHandler
	PkgRouter           *routing.Router
	networkInterface    *net.Interface
	tcpsequencer        = &port.Sequencer{}
)

// 补充缺失的结构体定义（原代码可能在其他文件，此处补全）
type PkgFlag int
const (
	Syn PkgFlag = iota
	Ack
	IcmpEchoRequest
	IcmpTimestampRequest
	IcmpAddressMaskRequest
	Ndp
	Arp
)
type PkgSend struct {
	ListenHandler *ListenHandler
	ip            string
	port          *port.Port
	flag          PkgFlag
}
type PkgResult struct {
	ipv4 string
	ipv6 string
	port *port.Port
}
type ListenHandler struct {
	Port             int
	SourceIp4        net.IP
	SourceHW         net.HardwareAddr
	SourceIP6        net.IP
	TcpConn4         net.PacketConn
	TcpConn6         net.PacketConn
	UdpConn4         net.PacketConn
	UdpConn6         net.PacketConn
	TcpChan          chan *PkgResult
	UdpChan          chan *PkgResult
	HostDiscoveryChan chan *PkgResult
	Phase            struct{ Is func(int) bool } // 简化Phase逻辑，保留原有接口
}
func NewListenHandler() *ListenHandler {
	return &ListenHandler{
		TcpChan:          make(chan *PkgResult, chanSize),
		UdpChan:          make(chan *PkgResult, chanSize),
		HostDiscoveryChan: make(chan *PkgResult, chanSize),
	}
}
func ToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
// Handlers contains the list of pcap handlers
type Handlers struct {
	InterfaceHandle   map[string]*pcap.Handle
	TransportActive   []*pcap.Handle
	LoopbackHandlers  []*pcap.Handle
	TransportInactive []*pcap.InactiveHandle
	EthernetActive    []*pcap.Handle
	EthernetInactive  []*pcap.InactiveHandle
}

func init() {
	if PkgRouter == nil || !privileges.IsPrivileged {
		return
	}

	transportPacketSend = make(chan *PkgSend, packetSendSize)

	var err error
	icmpConn4, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		gologger.Debug().Msgf("could not setup ip4:icmp: %s", err)
	}

	icmpConn6, err = icmp.ListenPacket("ip6:icmp", "::")
	if err != nil {
		gologger.Debug().Msgf("could not setup ip6:icmp: %s", err)
	}

	icmpPacketSend = make(chan *PkgSend, packetSendSize)
	ethernetPacketSend = make(chan *PkgSend, packetSendSize)

	// pre-reserve up to 10 ports
	for i := 0; i < NumberOfHandlers; i++ {
		listenHandler, err := buildListenHandler()
		if err != nil {
			return
		}

		ListenHandlers = append(ListenHandlers, listenHandler)
	}

	handlers = &Handlers{
		InterfaceHandle: make(map[string]*pcap.Handle),
	}
	if err := SetupHandlers(); err != nil {
		gologger.Error().Msgf("could not setup handlers: %s\n", err)
		return
	}
	go TransportReadWorker()
	go TransportWriteWorker()
	go ICMPWriteWorker()
}

func buildListenHandler() (*ListenHandler, error) {
	listenHandler := NewListenHandler()
	if port, err := freeport.GetFreeTCPPort(""); err != nil {
		return nil, fmt.Errorf("could not setup get free port: %s", err)
	} else {
		listenHandler.Port = port.Port
	}

	listenHandler.TcpChan = make(chan *PkgResult, chanSize)
	listenHandler.UdpChan = make(chan *PkgResult, chanSize)
	listenHandler.HostDiscoveryChan = make(chan *PkgResult, chanSize)

	var err error
	listenHandler.TcpConn4, err = net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		return nil, fmt.Errorf("could not setup ip4:tcp: %s", err)
	}
	listenHandler.UdpConn4, err = net.ListenIP("ip4:udp", &net.IPAddr{IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		return nil, fmt.Errorf("could not setup ip4:udp: %s", err)
	}

	listenHandler.TcpConn6, _ = net.ListenIP("ip6:tcp", &net.IPAddr{IP: net.ParseIP("::")})

	listenHandler.UdpConn6, _ = net.ListenIP("ip6:udp", &net.IPAddr{IP: net.ParseIP("::")})

	go listenHandler.ICMPReadWorker4()
	go listenHandler.ICMPReadWorker6()
	go listenHandler.TcpReadWorker4()
	go listenHandler.TcpReadWorker6()
	go listenHandler.UdpReadWorker4()
	go listenHandler.UdpReadWorker6()
	return listenHandler, nil
}

// ICMPWriteWorker writes packet to the network layer
func ICMPWriteWorker() {
	for pkg := range icmpPacketSend {
		switch pkg.flag {
		case IcmpEchoRequest:
			PingIcmpEchoRequestAsync(pkg.ip)
		case IcmpTimestampRequest:
			PingIcmpTimestampRequestAsync(pkg.ip)
		case IcmpAddressMaskRequest:
			PingIcmpAddressMaskRequestAsync(pkg.ip)
		case Ndp:
			PingNdpRequestAsync(pkg.ip)
		}
	}
}

// EthernetWriteWorker writes packet to the network layer
func EthernetWriteWorker() {
	for pkg := range ethernetPacketSend {
		switch pkg.flag {
		case Arp:
			ArpRequestAsync(pkg.ip)
		}
	}
}

// TCPWriteWorker that sends out TCP|UDP packets
func TransportWriteWorker() {
	for pkg := range transportPacketSend {
		SendAsyncPkg(pkg.ListenHandler, pkg.ip, pkg.port, pkg.flag)
	}
}

// SendAsyncPkg sends a single packet to a port
func SendAsyncPkg(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	isIP4 := iputil.IsIPv4(ip)
	isIP6 := iputil.IsIPv6(ip)
	isTCP := p.Protocol == protocol.TCP
	isUDP := p.Protocol == protocol.UDP
	switch {
	case isIP4 && isTCP:
		sendAsyncTCP4(listenHandler, ip, p, pkgFlag)
	case isIP4 && isUDP:
		sendAsyncUDP4(listenHandler, ip, p, pkgFlag)
	case isIP6 && isTCP:
		sendAsyncTCP6(listenHandler, ip, p, pkgFlag)
	case isIP6 && isUDP:
		sendAsyncUDP6(listenHandler, ip, p, pkgFlag)
	}
}

func sendAsyncTCP4(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	var eth layers.Ethernet
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}

	hasSourceIp := listenHandler.SourceIp4 != nil
	var iface *net.Interface
	if hasSourceIp && listenHandler.SourceHW != nil {
		// NOTE(dwisiswant0): Only attempt to use ethernet framing if we have
		// both source IP and HW.
		itf, gateway, _, err := PkgRouter.RouteWithSrc(listenHandler.SourceHW, listenHandler.SourceIp4, ip4.DstIP)
		if err != nil {
			gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
			return
		}
		gatewayMac, err := routing.GetGatewayMac(gateway.String())
		if err != nil {
			gologger.Debug().Msgf("could not find gateway MAC %s:%d: %s\n", ip, p.Port, err)
			return
		}

		eth = layers.Ethernet{
			EthernetType: layers.EthernetTypeIPv4,
			SrcMAC:       listenHandler.SourceHW,
			DstMAC:       gatewayMac,
		}
		ip4.SrcIP = listenHandler.SourceIp4
		iface = itf
	} else {
		if hasSourceIp {
			// NOTE(dwisiswant0): We have source IP but no HW, so use it
			// regular raw socket
			ip4.SrcIP = listenHandler.SourceIp4
		} else {
			_, _, sourceIP, err := PkgRouter.Route(ip4.DstIP)
			if err != nil {
				gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
				return
			} else if sourceIP == nil {
				gologger.Debug().Msgf("could not find correct source ipv4 for %s:%d\n", ip, p.Port)
				return
			}
			ip4.SrcIP = sourceIP
		}
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(listenHandler.Port),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	switch pkgFlag {
	case Syn:
		tcp.SYN = true
	case Ack:
		tcp.ACK = true
	}

	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	}

	if hasSourceIp && listenHandler.SourceHW != nil && iface != nil {
		err = sendWithHandler(ip, iface, &eth, &ip4, &tcp)
	} else {
		if listenHandler.TcpConn4 == nil {
			gologger.Debug().Msgf("TcpConn4 is nil, cannot send packet to %s:%d\n", ip, p.Port)
			return
		}

		err = sendWithConn(ip, listenHandler.TcpConn4, &tcp)
	}

	if err != nil {
		gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
	}
}

func sendAsyncUDP4(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
	}
	_, _, sourceIP, err := PkgRouter.Route(ip4.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv4 for %s:%d\n", ip, p.Port)
		return
	}

	if listenHandler.SourceIp4 != nil {
		ip4.SrcIP = listenHandler.SourceIp4
	} else {
		ip4.SrcIP = sourceIP
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(listenHandler.Port),
		DstPort: layers.UDPPort(p.Port),
	}

	err = udp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		if listenHandler.UdpConn4 == nil {
			gologger.Debug().Msgf("UdpConn4 is nil, cannot send packet to %s:%d\n", ip, p.Port)
			return
		}

		err = sendWithConn(ip, listenHandler.UdpConn4, &udp)
		if err != nil {
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
		}
	}
}

func sendAsyncTCP6(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip6 := layers.IPv6{
		DstIP:      net.ParseIP(ip),
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolTCP,
	}

	_, _, sourceIP, err := PkgRouter.Route(ip6.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv6 for %s:%d\n", ip, p.Port)
		return
	}

	if listenHandler.SourceIP6 != nil {
		ip6.SrcIP = listenHandler.SourceIP6
	} else {
		ip6.SrcIP = sourceIP
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(listenHandler.Port),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	switch pkgFlag {
	case Syn:
		tcp.SYN = true
	case Ack:
		tcp.ACK = true
	}

	err = tcp.SetNetworkLayerForChecksum(&ip6)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		if listenHandler.TcpConn6 == nil {
			gologger.Debug().Msgf("TcpConn6 is nil, cannot send packet to %s:%d\n", ip, p.Port)
			return
		}

		err = sendWithConn(ip, listenHandler.TcpConn6, &tcp)
		if err != nil {
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
		}
	}
}

func sendAsyncUDP6(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip6 := layers.IPv6{
		DstIP:      net.ParseIP(ip),
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolUDP,
	}

	_, _, sourceIP, err := PkgRouter.Route(ip6.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv6 for %s:%d\n", ip, p.Port)
		return
	}

	if listenHandler.SourceIP6 != nil {
		ip6.SrcIP = listenHandler.SourceIP6
	} else {
		ip6.SrcIP = sourceIP
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(listenHandler.Port),
		DstPort: layers.UDPPort(p.Port),
	}

	err = udp.SetNetworkLayerForChecksum(&ip6)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		if listenHandler.UdpConn6 == nil {
			gologger.Debug().Msgf("UdpConn6 is nil, cannot send packet to %s:%d\n", ip, p.Port)
			return
		}

		err = sendWithConn(ip, listenHandler.UdpConn6, &udp)
		if err != nil {
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
		}
	}
}

// ICMPReadWorker4 reads packets from the network layer
func (l *ListenHandler) ICMPReadWorker4() {
	data := make([]byte, 1500)
	for {
		if icmpConn4 == nil {
			return
		}
		n, addr, err := icmpConn4.ReadFrom(data)
		if err != nil {
			continue
		}

		rm, err := icmp.ParseMessage(ProtocolICMP, data[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeTimestampReply:
			l.HostDiscoveryChan <- &PkgResult{ipv4: addr.String()}
		}
	}
}

// ICMPReadWorker6 reads packets from the network layer
func (l *ListenHandler) ICMPReadWorker6() {
	if icmpConn6 == nil {
		return
	}
	data := make([]byte, 1500)
	for {
		n, addr, err := icmpConn6.ReadFrom(data)
		if err != nil {
			continue
		}

		rm, err := icmp.ParseMessage(ProtocolIPv6ICMP, data[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv6.ICMPTypeEchoReply:
			ip := addr.String()
			// check if it has [host]:port
			if ipSplit, _, err := net.SplitHostPort(ip); err == nil {
				ip = ipSplit
			}
			// drop zone
			if idx := strings.Index(ip, "%"); idx > 0 {
				ip = ip[:idx]
			}
			l.HostDiscoveryChan <- &PkgResult{ipv6: ip}
		}
	}
}

var defaultSerializeOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// send sends the given layers as a single packet on the network.
func sendWithConn(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	var err error

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, defaultSerializeOptions, l...); err != nil {
		return err
	}
	data := buf.Bytes()
	addr := &net.IPAddr{IP: net.ParseIP(destIP)}

	for retries := 0; retries < maxRetries; retries++ {
		_, err = conn.WriteTo(data, addr)
		if err == nil {
			return nil
		}

		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
	}

	if err != nil {
		return fmt.Errorf("could not send packet to %s: %s", destIP, err)
	}

	return nil
}

func sendWithHandler(destIP string, iface *net.Interface, l ...gopacket.SerializableLayer) error {
	var err error

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, defaultSerializeOptions, l...); err != nil {
		return err
	}
	data := buf.Bytes()

	// find the correct handler
	handler, ok := handlers.InterfaceHandle[iface.Name]
	if handler == nil || !ok {
		return errors.New("could not find correct pcap handler")
	}

	for retries := 0; retries < maxRetries; retries++ {
		err = handler.WritePacketData(data)
		if err == nil {
			return nil
		}

		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
	}

	if err != nil {
		return fmt.Errorf("could not send packet to %s: %s", destIP, err)
	}

	return nil
}

// TcpReadWorker4 优化版：添加错误处理+数据解析+CPU休眠
func (l *ListenHandler) TcpReadWorker4() {
	runtime.LockOSThread() // 绑定CPU核心，减少切换
	defer runtime.UnlockOSThread()

	data := make([]byte, 4096)
	for {
		if l.TcpConn4 == nil {
			gologger.Debug().Msg("TcpConn4 is nil, exit TCP read worker")
			return
		}

		n, addr, err := l.TcpConn4.ReadFrom(data)
		if err != nil {
			// 处理非阻塞错误：休眠后重试
			if strings.Contains(strings.ToLower(err.Error()), "eagain") || 
			   strings.Contains(strings.ToLower(err.Error()), "ewouldblock") {
				time.Sleep(readSleepMs * time.Millisecond)
				continue
			}
			// 处理套接字关闭/其他错误：退出循环
			gologger.Debug().Msgf("TCP4 read error (exit): %v", err)
			return
		}

		// 解析TCP数据包（原代码缺失，导致数据丢失+空循环）
		if n == 0 || addr == nil {
			continue
		}
		srcIP := addr.String()
		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			// 过滤目标端口匹配的数据包，发送到结果通道
			if tcp.DstPort == layers.TCPPort(l.Port) {
				l.TcpChan <- &PkgResult{
					ipv4: srcIP,
					port: &port.Port{
						Port:     int(tcp.SrcPort),
						Protocol: protocol.TCP,
					},
				}
			}
		}
	}
}

// TcpReadWorker6 优化版
func (l *ListenHandler) TcpReadWorker6() {
	if l.TcpConn6 == nil {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	data := make([]byte, 4096)
	for {
		n, addr, err := l.TcpConn6.ReadFrom(data)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "eagain") || 
			   strings.Contains(strings.ToLower(err.Error()), "ewouldblock") {
				time.Sleep(readSleepMs * time.Millisecond)
				continue
			}
			gologger.Debug().Msgf("TCP6 read error (exit): %v", err)
			return
		}

		if n == 0 || addr == nil {
			continue
		}
		srcIP := addr.String()
		// 处理IPv6地址格式（去除zone信息）
		if idx := strings.Index(srcIP, "%"); idx > 0 {
			srcIP = srcIP[:idx]
		}
		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			if tcp.DstPort == layers.TCPPort(l.Port) {
				l.TcpChan <- &PkgResult{
					ipv6: srcIP,
					port: &port.Port{
						Port:     int(tcp.SrcPort),
						Protocol: protocol.TCP,
					},
				}
			}
		}
	}
}

// UdpReadWorker4 优化版
func (l *ListenHandler) UdpReadWorker4() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	data := make([]byte, 4096)
	for {
		if l.UdpConn4 == nil {
			gologger.Debug().Msg("UdpConn4 is nil, exit UDP read worker")
			return
		}

		n, addr, err := l.UdpConn4.ReadFrom(data)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "eagain") || 
			   strings.Contains(strings.ToLower(err.Error()), "ewouldblock") {
				time.Sleep(readSleepMs * time.Millisecond)
				continue
			}
			gologger.Debug().Msgf("UDP4 read error (exit): %v", err)
			return
		}

		if n == 0 || addr == nil {
			continue
		}
		srcIP := addr.String()
		packet := gopacket.NewPacket(data[:n], layers.LayerTypeUDP, gopacket.Default)
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, ok := udpLayer.(*layers.UDP)
			if !ok {
				continue
			}
			if udp.DstPort == layers.UDPPort(l.Port) && udp.Length > 0 {
				l.UdpChan <- &PkgResult{
					ipv4: srcIP,
					port: &port.Port{
						Port:     int(udp.SrcPort),
						Protocol: protocol.UDP,
					},
				}
			}
		}
	}
}

// UdpReadWorker6 优化版
func (l *ListenHandler) UdpReadWorker6() {
	if l.UdpConn6 == nil {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	data := make([]byte, 4096)
	for {
		n, addr, err := l.UdpConn6.ReadFrom(data)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "eagain") || 
			   strings.Contains(strings.ToLower(err.Error()), "ewouldblock") {
				time.Sleep(readSleepMs * time.Millisecond)
				continue
			}
			gologger.Debug().Msgf("UDP6 read error (exit): %v", err)
			return
		}

		if n == 0 || addr == nil {
			continue
		}
		srcIP := addr.String()
		if idx := strings.Index(srcIP, "%"); idx > 0 {
			srcIP = srcIP[:idx]
		}
		packet := gopacket.NewPacket(data[:n], layers.LayerTypeUDP, gopacket.Default)
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, ok := udpLayer.(*layers.UDP)
			if !ok {
				continue
			}
			if udp.DstPort == layers.UDPPort(l.Port) && udp.Length > 0 {
				l.UdpChan <- &PkgResult{
					ipv6: srcIP,
					port: &port.Port{
						Port:     int(udp.SrcPort),
						Protocol: protocol.UDP,
					},
				}
			}
		}
	}
}
// SetupHandlerUnix on unix OS
// SetupHandlerUnix 优化版：固定合理的超时配置
func SetupHandlerUnix(interfaceName, bpfFilter string, protocols ...protocol.Protocol) error {
	for _, proto := range protocols {
		inactive, err := pcap.NewInactiveHandle(interfaceName)
		if err != nil {
			return fmt.Errorf("create inactive handle failed: %w", err)
		}

		// 基础配置：固定snaplen+超时+即时模式
		if err = inactive.SetSnapLen(snaplen); err != nil {
			inactive.CleanUp()
			return fmt.Errorf("set snaplen failed: %w", err)
		}

		// 核心优化：设置500ms阻塞超时，避免非阻塞空转
		readTimeout := time.Duration(readTimeoutMs) * time.Millisecond
		if err = inactive.SetTimeout(readTimeout); err != nil {
			inactive.CleanUp()
			CleanupHandlersUnix()
			return fmt.Errorf("set pcap timeout failed: %w", err)
		}

		if err = inactive.SetImmediateMode(true); err != nil {
			inactive.CleanUp()
			return fmt.Errorf("set immediate mode failed: %w", err)
		}

		// 按协议分类存储inactive handle
		switch proto {
		case protocol.TCP, protocol.UDP:
			handlers.TransportInactive = append(handlers.TransportInactive, inactive)
		case protocol.ARP:
			handlers.EthernetInactive = append(handlers.EthernetInactive, inactive)
		default:
			inactive.CleanUp()
			return errors.New("unsupported protocol: " + proto.String())
		}

		// 激活handle并设置BPF过滤
		handle, err := inactive.Activate()
		if err != nil {
			inactive.CleanUp()
			CleanupHandlersUnix()
			return fmt.Errorf("activate handle failed: %w", err)
		}

		if err = handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			inactive.CleanUp()
			CleanupHandlersUnix()
			return fmt.Errorf("set BPF filter failed: %w", err)
		}

		// 获取网卡信息并分类存储active handle
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			handle.Close()
			inactive.CleanUp()
			CleanupHandlersUnix()
			return fmt.Errorf("get interface %s failed: %w", interfaceName, err)
		}

		switch proto {
		case protocol.TCP, protocol.UDP:
			if iface.Flags&net.FlagLoopback == net.FlagLoopback {
				handlers.LoopbackHandlers = append(handlers.LoopbackHandlers, handle)
			} else {
				handlers.TransportActive = append(handlers.TransportActive, handle)
			}
			handlers.InterfaceHandle[iface.Name] = handle
		case protocol.ARP:
			handlers.EthernetActive = append(handlers.EthernetActive, handle)
		}
	}

	return nil
}
func TransportReadWorker() {
	var wgread sync.WaitGroup

	transportReaderCallback := func(tcp layers.TCP, udp layers.UDP, srcIP4, srcIP6 string) {
		for _, listenHandler := range ListenHandlers {
			// We consider only incoming packets
			tcpPortMatches := tcp.DstPort == layers.TCPPort(listenHandler.Port)
			udpPortMatches := udp.DstPort == layers.UDPPort(listenHandler.Port)
			sourcePortMatches := tcpPortMatches || udpPortMatches
			switch {
			case !sourcePortMatches:
				gologger.Debug().Msgf("Discarding Transport packet from non target ips: ip4=%s ip6=%s tcp_dport=%d udp_dport=%d\n", srcIP4, srcIP6, tcp.DstPort, udp.DstPort)
			case listenHandler.Phase.Is(HostDiscovery):
				proto := protocol.TCP
				if udpPortMatches {
					proto = protocol.UDP
				}
				listenHandler.HostDiscoveryChan <- &PkgResult{ipv4: srcIP4, ipv6: srcIP6, port: &port.Port{Port: int(tcp.SrcPort), Protocol: proto}}
			case tcpPortMatches && tcp.SYN && tcp.ACK:
				listenHandler.TcpChan <- &PkgResult{ipv4: srcIP4, ipv6: srcIP6, port: &port.Port{Port: int(tcp.SrcPort), Protocol: protocol.TCP}}
			case udpPortMatches && udp.Length > 0: // needs a better matching of udp payloads
				listenHandler.UdpChan <- &PkgResult{ipv4: srcIP4, ipv6: srcIP6, port: &port.Port{Port: int(udp.SrcPort), Protocol: protocol.UDP}}
			}
		}
	}

	// In case of OSX, when we decode the data from 'loO' interface
	// always get [Ethernet] layer only.
	// with the help of data received from packetSource.Packets() we can
	// extract the high level layers like [IPv4, IPv6, TCP, UDP]
	loopBackScanCaseCallback := func(handler *pcap.Handle, wg *sync.WaitGroup) {
		defer wg.Done()
		packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
		for packet := range packetSource.Packets() {
			tcp := &layers.TCP{}
			udp := &layers.UDP{}
			for _, layerType := range packet.Layers() {
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					ipLayer = packet.Layer(layers.LayerTypeIPv6)
					if ipLayer == nil {
						continue
					}
				}
				var srcIP4, srcIP6 string
				if ipv4, ok := ipLayer.(*layers.IPv4); ok {
					srcIP4 = ToString(ipv4.SrcIP)
				} else if ipv6, ok := ipLayer.(*layers.IPv6); ok {
					srcIP6 = ToString(ipv6.SrcIP)
				}

				var ok bool
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, ok = tcpLayer.(*layers.TCP)
					if !ok {
						continue
					}
				}
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, ok = udpLayer.(*layers.UDP)
					if !ok {
						continue
					}
				}

				if layerType.LayerType() == layers.LayerTypeTCP || layerType.LayerType() == layers.LayerTypeUDP {
					transportReaderCallback(*tcp, *udp, srcIP4, srcIP6)
				}
			}
		}
	}

	// Loopback Readers
	for _, handler := range handlers.LoopbackHandlers {
		wgread.Add(1)
		go loopBackScanCaseCallback(handler, &wgread)
	}

	// Transport Readers (TCP|UDP)
	for _, handler := range handlers.TransportActive {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				ip4 layers.IPv4
				ip6 layers.IPv6
				tcp layers.TCP
				udp layers.UDP
			)

			// Interfaces with MAC (Physical + Virtualized)
			parser4Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp)
			parser6Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &tcp, &udp)
			// Interfaces without MAC (TUN/TAP)
			parser4NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp)
			parser6NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp, &udp)

			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers,
				parser4Mac, parser6Mac,
				parser4NoMac, parser6NoMac,
			)

			decoded := []gopacket.LayerType{}
			for {
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

				for _, parser := range parsers {
					err := parser.DecodeLayers(data, &decoded)
					if err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeTCP || layerType == layers.LayerTypeUDP {
							srcIP4 := ToString(ip4.SrcIP)
							srcIP6 := ToString(ip6.SrcIP)
							transportReaderCallback(tcp, udp, srcIP4, srcIP6)
						}
					}
				}
			}
		}(handler)
	}

	// Ethernet Readers
	for _, handler := range handlers.EthernetActive {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				arp layers.ARP
			)

			parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
			parser4.IgnoreUnsupported = true
			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers, parser4)

			decoded := []gopacket.LayerType{}

			for {
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

				for _, parser := range parsers {
					err := parser.DecodeLayers(data, &decoded)
					if err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeARP {
							// check if the packet was sent out
							isReply := arp.Operation == layers.ARPReply
							var sourceMacIsInterfaceMac bool
							if networkInterface != nil {
								sourceMacIsInterfaceMac = bytes.Equal([]byte(networkInterface.HardwareAddr), arp.SourceHwAddress)
							}
							isOutgoingPacket := !isReply || sourceMacIsInterfaceMac
							if isOutgoingPacket {
								continue
							}
							srcIP4 := net.IP(arp.SourceProtAddress)

							for _, listenHandler := range ListenHandlers {
								listenHandler.HostDiscoveryChan <- &PkgResult{ipv4: ToString(srcIP4)}
							}
						}
					}
				}
			}
		}(handler)
	}

	wgread.Wait()
}

// CleanupHandlers for all interfaces
func CleanupHandlersUnix() {
	allActive := append(handlers.TransportActive, handlers.EthernetActive...)
	allActive = append(allActive, handlers.LoopbackHandlers...)
	for _, handler := range allActive {
		handler.Close()
	}
	allInactive := append(handlers.TransportInactive, handlers.EthernetInactive...)
	for _, inactiveHandler := range allInactive {
		inactiveHandler.CleanUp()
	}
}

func SetupHandlers() error {
	if NetworkInterface != "" {
		return SetupHandler(NetworkInterface)
	}

	// listen on all interfaces manually
	// unfortunately s.SetupHandler("any") causes ip4 to be ignored
	itfs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range itfs {
		isInterfaceDown := itf.Flags&net.FlagUp == 0
		if isInterfaceDown {
			continue
		}
		if err := SetupHandler(itf.Name); err != nil {
			gologger.Warning().Msgf("Error on interface %s: %s", itf.Name, err)
		}
	}

	return nil
}

func SetupHandler(interfaceName string) error {
	var portFilters []string
	for _, listenHandler := range ListenHandlers {
		portFilters = append(portFilters, fmt.Sprintf("dst port %d", listenHandler.Port))
	}

	bpfFilter := fmt.Sprintf("(%s) and (tcp or udp)", strings.Join(portFilters, " or "))
	err := SetupHandlerUnix(interfaceName, bpfFilter, protocol.TCP)
	if err != nil {
		return err
	}
	// arp filter should be improved with source mac
	// https://stackoverflow.com/questions/40196549/bpf-expression-to-capture-only-arp-reply-packets
	// (arp[6:2] = 2) and dst host host and ether dst mac
	bpfFilter = "arp"
	err = SetupHandlerUnix(interfaceName, bpfFilter, protocol.ARP)
	if err != nil {
		return err
	}

	return nil
}

// ACKPort sends an ACK packet to a port
func ACKPort(listenHandler *ListenHandler, dstIP string, port int, timeout time.Duration) (bool, error) {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

	rawPort, err := freeport.GetFreeTCPPort("")
	if err != nil {
		return false, err
	}

	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}

	_, _, sourceIP, err := PkgRouter.Route(ip4.DstIP)
	if err != nil {
		return false, err
	}

	if listenHandler.SourceIp4 != nil {
		ip4.SrcIP = listenHandler.SourceIp4
	} else {
		ip4.SrcIP = sourceIP
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x12, 0x34},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort.Port),
		DstPort: layers.TCPPort(port),
		ACK:     true,
		Window:  1024,
		Seq:     tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return false, err
	}

	err = sendWithConn(dstIP, conn, &tcp)
	if err != nil {
		return false, err
	}

	data := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(data)
		if err != nil {
			break
		}

		// not matching ip
		if addr.String() != dstIP {
			gologger.Debug().Msgf("Discarding TCP packet from non target ip %s for %s\n", dstIP, addr.String())
			continue
		}

		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			// We consider only incoming packets
			if tcp.DstPort != layers.TCPPort(rawPort.Port) {
				gologger.Debug().Msgf("Discarding TCP packet from %s:%d not matching %s:%d port\n", addr.String(), tcp.DstPort, dstIP, rawPort.Port)
				continue
			} else if tcp.RST {
				gologger.Debug().Msgf("Accepting RST packet from %s:%d\n", addr.String(), tcp.DstPort)
				return true, nil
			}
		}
	}

	return false, nil
}
