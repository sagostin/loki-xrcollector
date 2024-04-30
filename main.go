package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
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

var geoIpDB *geoip2.Reader

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Use %s like: %s [option]\n", "heplify-xrcollector 0.4", os.Args[0])
		flag.PrintDefaults()
	}

	/*flag.StringVar(&cfg.HepServerAddress, "hs", "127.0.0.1:9060", "HEP server address over TLS")*/
	flag.StringVar(&cfg.CollectorAddressTLS, "tls", ":7060", "XR collector TLS listen address")
	flag.StringVar(&cfg.CollectorAddressUDP, "udp", ":7060", "XR collector UDP listen address")
	flag.BoolVar(&cfg.Debug, "debug", true, "Log with debug level")

	flag.StringVar(&lokiURL, "lokiURL", "", "URL to Loki's push API")
	flag.StringVar(&lokiUser, "lokiUser", "", "Username for Loki")
	flag.StringVar(&lokiPass, "lokiPass", "", "Password for Loki")
	flag.StringVar(&cfg.GeoIpFile, "geoIpDB", "./GeoLite2-City.mmdb", "Path to GeoIP2 database")
	flag.BoolVar(&cfg.DeviceLookup, "deviceLookup", true, "Lookup device information in MAC database")
	flag.StringVar(&cfg.DeviceLookupAuth, "deviceLookupAuth", "admin:admin", "Lookup device information basic auth creds") // will enable grabbing of device information from ConnectWise
	flag.StringVar(&cfg.DeviceLookupURL, "deviceLookupURL", "http://localhost:8080", "URL to device lookup service")

	flag.Parse()

	if lokiURL != "" {
		lokiClient = NewLokiClient(lokiURL, lokiUser, lokiPass)
	}
}

var lokiURL, lokiUser, lokiPass string
var lokiClient *LokiClient

func main() {
	deviceCacheMap = make(map[string][]string)

	ticker := time.NewTicker(8 * time.Hour)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				// Fetch and zultysHostedCache the companies every tick
				log.Info("Fetching devices for cache")
				err := fetchDevices()
				if err != nil {
					log.Error(err)
				}
			}
		}
	}()

	db, err := geoip2.Open(cfg.GeoIpFile)
	if err != nil {
		log.Fatal(err)
	}
	geoIpDB = db

	defer func(db *geoip2.Reader) {
		err := db.Close()
		if err != nil {
			log.Error(err)
		}
	}(db)

	go startTLS()
	go startUDP()

	select {}
}

func startUDP() {
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

	log.Info("Starting UDP listener")

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

	log.Info("Starting TLS listener")

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

var deviceCacheMap map[string][]string

func fetchDevices() error {
	// Create a new request
	req, err := http.NewRequest("GET", cfg.DeviceLookupURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	auth := strings.Split(cfg.DeviceLookupAuth, ":")

	// Set basic auth if credentials are provided
	if auth[0] != "" && auth[1] != "" {
		req.SetBasicAuth(auth[0], auth[1])
	}

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to DeviceLookup: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("DeviceLookup response:", string(responseBody)) // Print response body for debugging

	err = json.Unmarshal(responseBody, &deviceCacheMap)
	if err != nil {
		return err
	}

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 response status: %d", resp.StatusCode)
	}

	return nil
}
