package main

import (
	"log"
	"net"
)

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

func sendHEP(conn net.Conn, outHEPCh chan []byte) {
	for packet := range outHEPCh {
		for len(packet) > 0 {
			// don't send hep, just output log for now
			log.Printf("HEP: %s\n", packet)
			// todo send to loki & get geo position based on IP??
		}
	}
}
