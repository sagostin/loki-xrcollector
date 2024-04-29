package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/negbie/sipparser"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"strconv"
	"time"
)

// XRPacket holds UDP data and address, updated to TCP for TLS
type XRPacket struct {
	addr net.Addr
	data []byte
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Use %s like: %s [option]\n", "heplify-xrcollector 0.4", os.Args[0])
		flag.PrintDefaults()
	}

	/*flag.StringVar(&cfg.HepServerAddress, "hs", "127.0.0.1:9060", "HEP server address over TLS")*/
	flag.StringVar(&cfg.CollectorAddress, "xs", ":7060", "XR collector TLS listen address")
	flag.BoolVar(&cfg.Debug, "debug", true, "Log with debug level")

	flag.StringVar(&lokiURL, "lokiURL", "", "URL to Loki's push API")
	flag.StringVar(&lokiUser, "lokiUser", "", "Username for Loki")
	flag.StringVar(&lokiPass, "lokiPass", "", "Password for Loki")
	flag.Parse()

	if lokiURL != "" {
		lokiClient = NewLokiClient(lokiURL, lokiUser, lokiPass)

		marshal, err := json.Marshal(lokiClient)
		if err != nil {
			return
		}
		log.Info(string(marshal))
	}
}

var lokiURL, lokiUser, lokiPass string
var lokiClient *LokiClient

func main() {
	tlsConfig := loadTLSConfig()
	listener, err := tls.Listen("tcp", cfg.CollectorAddress, tlsConfig)
	if err != nil {
		log.Fatalln(err)
	}
	defer listener.Close()

	/*connHEP, err := tls.Dial("tcp", cfg.HepServerAddress, nil) // Optional: provide *tls.Config
	if err != nil {
		log.Fatalln(err)
	}
	defer connHEP.Close()*/

	inXRCh := make(chan XRPacket, 100)
	outXRCh := make(chan XRPacket, 100)
	outHEPCh := make(chan []byte, 100)

	go recvXR(listener, inXRCh, outHEPCh)
	go sendXR(listener, outXRCh)
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

const maxPktSize = 4096

func recvXR(listener net.Listener, inXRCh chan XRPacket, outHEPCh chan []byte) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting: ", err.Error())
			continue
		}
		go handleConnection(conn, inXRCh, outHEPCh)
	}
}

func handleConnection(conn net.Conn, inXRCh chan XRPacket, outHEPCh chan []byte) {
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
		labels := map[string]string{"job": "vqrtcpxr", "from_user": sipmsg.From.URI.User, "from_host": sipmsg.From.URI.Host, "contact_host": sipmsg.ContactHost}
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

		inXRCh <- XRPacket{conn.RemoteAddr(), msg}
		outHEPCh <- data
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
