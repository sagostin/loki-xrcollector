package main

var cfg config

type config struct {
	HepServerAddress    string
	CollectorAddressTLS string
	CollectorAddressUDP string
	GeoIpFile           string
	DeviceLookup        bool
	DeviceLookupURL     string
	DeviceLookupAuth    string
	HepNodeID           uint
	Debug               bool
}
