package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/negbie/sipparser"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func sendLokiLog(sipMsg sipparser.SipMsg, device string, lanAddr string, wanAddr string) error {
	ip := net.ParseIP(strings.Split(wanAddr, ":")[0])
	geoIpRecord, err := geoIpDB.City(ip)
	if err != nil {
		log.Error(err)
	}

	// todo grab customer / info based on device MAC using cached list of devices using ConnectWise linker

	labels := map[string]string{
		"job":        "vqrtcpxr",
		"device":     device,
		"lan_addr":   lanAddr,
		"wan_addr":   ip.String(),
		"city":       geoIpRecord.City.Names["en"],
		"region":     geoIpRecord.Subdivisions[0].Names["en"],
		"country":    geoIpRecord.Country.Names["en"],
		"user_agent": sipMsg.UserAgent,
		/*"lat": geoIpRecord.Location.Latitude,
		"long": geoIpRecord.Location.Longitude,
		"customer": "todo using connectwise",*/
	}

	log.Info("Sender has multiple subdivisions/regions: ", geoIpRecord.Subdivisions)

	vqRtcpXr := parseSipMsg(&sipMsg)
	vqRtcpXr.Extra = VqExtra{
		Latitude:  strconv.FormatFloat(geoIpRecord.Location.Latitude, 'f', -1, 64),
		Longitude: strconv.FormatFloat(geoIpRecord.Location.Longitude, 'f', -1, 64),
		Country:   geoIpRecord.Country.Names["en"],
		City:      geoIpRecord.City.Names["en"],
		Region:    geoIpRecord.Subdivisions[0].Names["en"],
	}

	marshal, err := json.Marshal(vqRtcpXr)
	if err != nil {
		return err
	}

	logEntry := LogEntry{
		Timestamp: strconv.FormatInt(time.Now().UnixNano(), 10), // todo handle time better?
		Line:      string(marshal),
	}

	return lokiClient.PushLog(labels, logEntry)
}

type VqRtcpXr struct {
	VqReport      string    `json:"vqReport,omitempty"` // this is the header for if it is an alert or call term type
	CallID        string    `json:"callID,omitempty"`
	LocalID       string    `json:"localID,omitempty"`
	RemoteID      string    `json:"remoteID,omitempty"`
	OrigID        string    `json:"origID,omitempty"`
	RemoteGroupID string    `json:"remoteGroupID,omitempty"`
	LocalAddr     string    `json:"localAddr,omitempty"`
	RemoteAddr    string    `json:"remoteAddr,omitempty"`
	LocalMetrics  VqMetrics `json:"localMetrics,omitempty"`
	RemoteMetrics VqMetrics `json:"remoteMetrics,omitempty"`
	Extra         VqExtra   `json:"extra,omitempty"`
	DialogID      string    `json:"dialogID,omitempty"`
}

type VqMetrics struct {
	StartTimestamp string `json:"startTimestamp,omitempty"`
	StopTimestamp  string `json:"stopTimestamp,omitempty"`
	SessionDesc    string `json:"sessionDesc,omitempty"`
	JitterBuffer   string `json:"jitterBuffer,omitempty"`
	PacketLoss     string `json:"packetLoss,omitempty"`
	BurstGapLoss   string `json:"burstGapLoss,omitempty"`
	Delay          string `json:"delay,omitempty"`
	QualityEst     string `json:"qualityEst,omitempty"`
}

type VqExtra struct {
	Latitude  string `json:"latitude,omitempty"`
	Longitude string `json:"longitude,omitempty"`
	Country   string `json:"country,omitempty"`
	City      string `json:"city,omitempty"`
	Region    string `json:"region,omitempty"`
	Customer  string `json:"customer,omitempty"` // look up using external API that we store for a period?
	System    string `json:"system,omitempty"`   // look up using external API that we store for a period?
}

func parseSipMsg(sipMsg *sipparser.SipMsg) VqRtcpXr {

	replaceRLine := strings.Replace(sipMsg.Body, "\r", "", -1)
	msg := strings.Split(replaceRLine, "\n")

	var state = "start"

	var vqRtcpXr = VqRtcpXr{}
	var localMetrics = VqMetrics{}
	var remoteMetrics = VqMetrics{}

	for _, line := range msg {
		// runs when we haven't processed anything else
		if state == "start" {
			if strings.HasPrefix(line, "VQSessionReport") || strings.HasPrefix(line, "VQAlertReport") {
				vqReport := strings.Split(line, ":")[1]
				vqReport = strings.TrimSpace(vqReport)
				fmt.Println("vqReport: ", vqReport)
				vqRtcpXr.VqReport = vqReport
				continue
			}

			parseMainLines(line, "VQSessionReport", &vqRtcpXr)
			parseMainLines(line, "VQAlertReport", &vqRtcpXr)
			parseMainLines(line, "CallID", &vqRtcpXr)
			parseMainLines(line, "LocalID", &vqRtcpXr)
			parseMainLines(line, "RemoteID", &vqRtcpXr)
			parseMainLines(line, "OrigID", &vqRtcpXr)
			parseMainLines(line, "RemoteGroupID", &vqRtcpXr)
			parseMainLines(line, "LocalAddr", &vqRtcpXr)
			parseMainLines(line, "RemoteAddr", &vqRtcpXr)
		}

		parseMainLines(line, "DialogID", &vqRtcpXr)

		if strings.HasPrefix(line, "LocalMetrics") {
			state = "localMetrics"
			continue
		}

		if strings.HasPrefix(line, "RemoteMetrics") {
			state = "remoteMetrics"
			continue
		}

		var interfaceToUse *VqMetrics
		if state == "localMetrics" {
			interfaceToUse = &localMetrics
		} else if state == "remoteMetrics" {
			interfaceToUse = &remoteMetrics
		}

		parseMetricLines(line, "Timestamps", interfaceToUse)
		parseMetricLines(line, "SessionDesc", interfaceToUse)
		parseMetricLines(line, "JitterBuffer", interfaceToUse)
		parseMetricLines(line, "PacketLoss", interfaceToUse)
		parseMetricLines(line, "BurstGapLoss", interfaceToUse)
		parseMetricLines(line, "Delay", interfaceToUse)
		parseMetricLines(line, "QualityEst", interfaceToUse)

		continue

	}

	vqRtcpXr.LocalMetrics = localMetrics
	vqRtcpXr.RemoteMetrics = remoteMetrics

	return vqRtcpXr
}

func parseMetricLines(line, prefix string, metric *VqMetrics) {
	if strings.HasPrefix(line, prefix) {
		value := strings.TrimSpace(strings.TrimPrefix(line, prefix+":"))

		switch prefix {
		case "Timestamps":
			parts := strings.Split(value, " ")
			start := strings.Split(parts[0], "=")[1]
			stop := strings.Split(parts[1], "=")[1]
			metric.StartTimestamp = start
			metric.StopTimestamp = stop
		case "SessionDesc":
			metric.SessionDesc = value
		case "JitterBuffer":
			metric.JitterBuffer = value
		case "PacketLoss":
			metric.PacketLoss = value
		case "BurstGapLoss":
			metric.BurstGapLoss = value
		case "Delay":
			metric.Delay = value
		case "QualityEst":
			metric.QualityEst = value
		}
	}
}

func parseMainLines(line, prefix string, report *VqRtcpXr) {
	if strings.HasPrefix(line, prefix) {
		value := strings.TrimSpace(strings.TrimPrefix(line, prefix+":"))
		switch prefix {
		case "VQSessionReport", "VQAlertReport":
			report.VqReport = value
		case "CallID":
			report.CallID = value
		case "LocalID":
			report.LocalID = value
		case "RemoteID":
			report.RemoteID = value
		case "OrigID":
			report.OrigID = value
		case "RemoteGroupID":
			report.RemoteGroupID = value
		case "LocalAddr":
			report.LocalAddr = value
		case "RemoteAddr":
			report.RemoteAddr = value
		}
	}
}

// LokiClient holds the configuration for the Loki client.
type LokiClient struct {
	PushURL  string // URL to Loki's push API
	Username string // Username for basic auth
	Password string // Password for basic auth
}

// LogEntry represents a single log entry.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Line      string `json:"line"`
}

// LokiPushData represents the data structure required by Loki's push API.
type LokiPushData struct {
	Streams []LokiStream `json:"streams"`
}

// LokiStream represents a stream of logs with the same labels in Loki.
type LokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"` // Array of [timestamp, line] tuples
}

// NewLokiClient creates a new client to interact with Loki.
func NewLokiClient(pushURL, username, password string) *LokiClient {
	return &LokiClient{
		PushURL:  pushURL,
		Username: username,
		Password: password,
	}
}

// PushLog sends a log entry to Loki.
func (c *LokiClient) PushLog(labels map[string]string, entry LogEntry) error {
	// Prepare the payload
	payload := LokiPushData{
		Streams: []LokiStream{
			{
				Stream: labels,
				Values: [][2]string{{entry.Timestamp, entry.Line}},
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling json: %w", err)
	}

	// Create a new request
	req, err := http.NewRequest("POST", c.PushURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Set basic auth if credentials are provided
	if c.Username != "" && c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to Loki: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Loki response:", string(responseBody)) // Print response body for debugging
	marshal, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	log.Warnf("Loki response: %s", string(marshal))

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 response status: %d", resp.StatusCode)
	}

	return nil
}
