package main

import (
	"fmt"
	"github.com/negbie/sipparser"
	log "github.com/sirupsen/logrus"
	"net"
)

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
		var sipMsg *sipparser.SipMsg
		if msg, sipMsg, err = process(data); err != nil {
			log.Println(err)
			continue
		}

		// todo include OrigID in labels instead of from_host, and include from_user as "device"
		// todo have geo ip for lat and long based on sender address
		// todo contact_host renamed to something more obvious because it is used for the local address of the sender
		// todo include general stats like jitter, packet loss, etc. in labels?
		// todo include region of geoip information in labels? eg. "region": "Kelowna" or "region": "Penticton"

		err = sendLokiLog(*sipMsg, sipMsg.From.URI.User, sipMsg.ContactHost, addr.String())
		if err != nil {
			log.Errorf("Failed to push log to Loki: %v\n", err)
		}

		inXRCh <- XRPacketUDP{addr, msg}
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
		var sipMsg *sipparser.SipMsg
		if msg, sipMsg, err = process(data); err != nil {
			log.Println(err)
			continue
		}
		err = sendLokiLog(*sipMsg, sipMsg.From.URI.User, sipMsg.ContactHost, conn.RemoteAddr().String())
		if err != nil {
			log.Errorf("Failed to push log to Loki: %v\n", err)
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

func sendTLS(listener net.Listener, outXRCh chan XRPacketTLS) {
	for packet := range outXRCh {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting: ", err.Error())
			continue
		}
		_, err = conn.Write(packet.data)
		err = conn.Close()
		if err != nil {
			log.Println("Error closing connection: ", err.Error())
			return
		}
		if err != nil {
			log.Println("Error sending: ", err.Error())
			continue
		}
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

func sendHEP(conn net.Conn, outHEPCh chan []byte) {
	for packet := range outHEPCh {
		for len(packet) > 0 {
			// don't send hep, just output log for now
			log.Printf("HEP: %s\n", packet)
			// todo send to loki & get geo position based on IP??
		}
	}
}
