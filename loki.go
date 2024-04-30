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
		"job":      "vqrtcpxr",
		"device":   device,
		"lan_addr": lanAddr,
		"wan_addr": ip.String(),
		"city":     geoIpRecord.City.Names["en"],
		/*"lat": geoIpRecord.Location.Latitude,
		"long": geoIpRecord.Location.Longitude,
		"customer": "todo using connectwise",*/
	}

	logEntry := LogEntry{
		Timestamp: strconv.FormatInt(time.Now().UnixNano(), 10), // todo handle time better?
		Line:      sipMsg.Body,
	}

	return lokiClient.PushLog(labels, logEntry)
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
