package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/negbie/sipparser"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"strconv"
	"time"
)

// XRPacketTLS holds UDP data and address, updated to TCP for TLS
type XRPacketTLS struct {
	addr net.Addr
	data []byte
}

// XRPacketUDP holds data and address, updated to TCP for TLS
type XRPacketUDP struct {
	addr *net.UDPAddr
	data []byte
}

const maxPktSize = 4096

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Use %s like: %s [option]\n", "heplify-xrcollector 0.4", os.Args[0])
		flag.PrintDefaults()
	}

	/*flag.StringVar(&cfg.HepServerAddress, "hs", "127.0.0.1:9060", "HEP server address over TLS")*/
	flag.StringVar(&cfg.CollectorAddressTLS, "tls", ":7060", "XR collector TLS listen address")
	flag.StringVar(&cfg.CollectorAddressTLS, "udp", ":7060", "XR collector UDP listen address")
	flag.BoolVar(&cfg.Debug, "debug", true, "Log with debug level")

	flag.StringVar(&lokiURL, "lokiURL", "", "URL to Loki's push API")
	flag.StringVar(&lokiUser, "lokiUser", "", "Username for Loki")
	flag.StringVar(&lokiPass, "lokiPass", "", "Password for Loki")
	flag.Parse()

	if lokiURL != "" {
		lokiClient = NewLokiClient(lokiURL, lokiUser, lokiPass)
	}
}

var lokiURL, lokiUser, lokiPass string
var lokiClient *LokiClient

func main() {
	go startTLS()
	go startUDP()
}

func startUDP() {
	log.Info("Starting UDP listener")
	addrXR, err := net.ResolveUDPAddr("udp", cfg.CollectorAddressUDP)
	if err != nil {
		log.Fatalln(err)
	}

	connXR, err := net.ListenUDP("udp", addrXR)
	if err != nil {
		log.Fatalln(err)
	}

	inXRCh := make(chan XRPacketUDP, 100)
	outXRCh := make(chan XRPacketUDP, 100)

	go handleUDP(connXR, inXRCh)
	go sendUDP(connXR, outXRCh)

	for packet := range inXRCh {
		outXRCh <- packet
	}
}

func startTLS() {
	tlsConfig := loadTLSConfig()
	listener, err := tls.Listen("tcp", cfg.CollectorAddressTLS, tlsConfig)
	if err != nil {
		log.Fatalln(err)
	}
	defer listener.Close()

	inXRCh := make(chan XRPacketTLS, 100)
	outXRCh := make(chan XRPacketTLS, 100)

	go recvTLS(listener, inXRCh)
	go sendTLS(listener, outXRCh)
	/*go sendHEP(connHEP, outHEPCh)*/

	for packet := range inXRCh {
		outXRCh <- packet
	}
}

func loadTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

func handleUDP(conn *net.UDPConn, inXRCh chan XRPacketUDP) {
	defer func(conn *net.UDPConn) {
		err := conn.Close()
		if err != nil {
			log.Println("Error closing connection: ", err)
		}
	}(conn)
	buffer := make([]byte, maxPktSize)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error on XR read: ", err)
			continue
		}
		data := buffer[:n]
		if n >= maxPktSize {
			log.Printf("Warning received packet from %s exceeds %d bytes\n", addr, maxPktSize)
		}
		if cfg.Debug {
			log.Printf("Received following RTCP-XR report with %d bytes from %s:\n%s\n", n, addr, string(data))
		} else {
			log.Printf("Received packet with %d bytes from %s\n", n, addr)
		}
		var msg []byte
		var sipmsg *sipparser.SipMsg
		if msg, sipmsg, err = process(data); err != nil {
			log.Println(err)
			continue
		}
		labels := map[string]string{
			"job":          "vqrtcpxr",
			"from_user":    sipmsg.From.URI.User,
			"from_host":    sipmsg.From.URI.Host,
			"contact_host": sipmsg.ContactHost,
			"xr_addr":      addr.String()}
		logEntry := LogEntry{
			Timestamp: strconv.FormatInt(time.Now().UnixNano(), 10), // todo handle time better?
			Line:      sipmsg.Body,
		}

		err = lokiClient.PushLog(labels, logEntry)

		if err != nil {
			fmt.Printf("Failed to push log to Loki: %v\n", err)
		} else {
			fmt.Println("Log pushed to Loki successfully.")
		}

		inXRCh <- XRPacketUDP{addr, msg}
	}
}

func sendUDP(conn *net.UDPConn, outXRCh chan XRPacketUDP) {
	for packet := range outXRCh {
		n, err := conn.WriteToUDP(packet.data, packet.addr)
		if err != nil {
			log.Println("Error on XR write: ", err)
			continue
		}
		if cfg.Debug {
			log.Printf("Sent following SIP/2.0 200 OK with %d bytes to %s:\n%s\n", n, packet.addr, string(packet.data))
		} else {
			log.Printf("Sent back OK with %d bytes to %s\n", n, packet.addr)
		}
	}
}

func recvTLS(listener net.Listener, inXRCh chan XRPacketTLS) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting: ", err.Error())
			continue
		}
		go handleTLS(conn, inXRCh)
	}
}

func handleTLS(conn net.Conn, inXRCh chan XRPacketTLS) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Println("Error closing connection: ", err)
		}
	}(conn)
	buffer := make([]byte, maxPktSize)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			log.Println("Error on XR read: ", err)
			continue
		}
		data := buffer[:n]
		if n >= maxPktSize {
			log.Printf("Warning received packet from %s exceeds %d bytes\n", conn.RemoteAddr(), maxPktSize)
		}
		if cfg.Debug {
			log.Printf("Received following RTCP-XR report with %d bytes from %s:\n%s\n", n, conn.RemoteAddr(), string(data))
		} else {
			log.Printf("Received packet with %d bytes from %s\n", n, conn.RemoteAddr())
		}
		var msg []byte
		var sipmsg *sipparser.SipMsg
		if msg, sipmsg, err = process(data); err != nil {
			log.Println(err)
			continue
		}
		labels := map[string]string{
			"job":          "vqrtcpxr",
			"from_user":    sipmsg.From.URI.User,
			"from_host":    sipmsg.From.URI.Host,
			"contact_host": sipmsg.ContactHost,
			"xr_addr":      conn.RemoteAddr().String()}
		logEntry := LogEntry{
			Timestamp: strconv.FormatInt(time.Now().UnixNano(), 10), // todo handle time better?
			Line:      sipmsg.Body,
		}

		err = lokiClient.PushLog(labels, logEntry)

		if err != nil {
			fmt.Printf("Failed to push log to Loki: %v\n", err)
		} else {
			fmt.Println("Log pushed to Loki successfully.")
		}

		inXRCh <- XRPacketTLS{conn.RemoteAddr(), msg}
	}
}

func process(pkt []byte) ([]byte, *sipparser.SipMsg, error) {
	sip := sipparser.ParseMsg(string(pkt))
	if sip.Error != nil {
		return nil, nil, sip.Error
	}
	if sip.ContentType != "application/vq-rtcpxr" || len(sip.Body) < 32 ||
		sip.From == nil || sip.To == nil || sip.Cseq == nil {
		return nil, nil, fmt.Errorf("No or malformed vq-rtcpxr inside SIP Message:\n%s", sip.Msg)
	}

	resp := fmt.Sprintf("SIP/2.0 200 OK\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=Fg2Uy0r7geBQF\r\nContact: %s\r\n"+
		"Call-ID: %s\r\nCseq: %s\r\nUser-Agent: heplify-xrcollector\r\nContent-Length: 0\r\n\r\n",
		sip.ViaOne,
		sip.From.Val,
		sip.To.Val,
		sip.ContactVal,
		sip.CallID,
		sip.Cseq.Val)
	return []byte(resp), sip, nil
}
