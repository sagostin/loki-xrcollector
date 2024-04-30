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
		Latitude:  geoIpRecord.Location.Latitude,
		Longitude: geoIpRecord.Location.Longitude,
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
	StartTimestamp string       `json:"startTimestamp,omitempty"`
	StopTimestamp  string       `json:"stopTimestamp,omitempty"`
	SessionDesc    SessionDesc  `json:"sessionDesc,omitempty"`
	JitterBuffer   JitterBuffer `json:"jitterBuffer,omitempty"`
	PacketLoss     PacketLoss   `json:"packetLoss,omitempty"`
	BurstGapLoss   BurstGapLoss `json:"burstGapLoss,omitempty"`
	Delay          Delay        `json:"delay,omitempty"`
	QualityEst     QualityEst   `json:"qualityEst,omitempty"`
}

type SessionDesc struct {
	PayloadType             string `json:"payloadType,omitempty"`
	PayloadDescription      string `json:"payloadDescription,omitempty"`
	SampleRate              string `json:"sampleRate,omitempty"`
	FrameDuration           string `json:"frameDuration,omitempty"`
	FrameOctets             string `json:"frameOctets,omitempty"`
	FramesPerPackets        string `json:"framesPerPackets,omitempty"`
	PacketLossConcealment   string `json:"packetLossConcealment,omitempty"`
	SilenceSuppressionState string `json:"silenceSuppressionState,omitempty"`
}

type JitterBuffer struct {
	Adaptive string `json:"adaptive,omitempty"` // indicates the jitter buffer in the endpoint ("0" - unknown; "1" - reserved; "2" - non-adaptive; "3" - adaptive)
	Rate     string `json:"rate,omitempty"`
	Nominal  string `json:"nominal,omitempty"`
	Max      string `json:"max,omitempty"`
	AbsMax   string `json:"absMax,omitempty"`
}

type PacketLoss struct {
	NetworkPacketLossRate   string `json:"networkPacketLossRate,omitempty"`
	JitterBufferDiscardRate string `json:"jitterBufferDiscardRate,omitempty"`
}

type BurstGapLoss struct {
	BurstLossDensity string `json:"burstLossDensity,omitempty"`
	BurstDuration    string `json:"burstDuration,omitempty"`
	GapLossDensity   string `json:"gapLossDensity,omitempty"`
	GapDuration      string `json:"gapDuration,omitempty"`
}

type Delay struct {
	RoundTrip          string `json:"roundTrip,omitempty"`
	EndSystem          string `json:"endSystem,omitempty"`
	OneWay             string `json:"oneWay,omitempty"`
	InterArrivalJitter string `json:"interArrivalJitter,omitempty"`
	MeanAbsoluteJitter string `json:"meanAbsoluteJitter,omitempty"`
}

type QualityEst struct {
	ListeningQualityR      string `json:"listeningQualityR,omitempty"`
	RLQEstAlg              string `json:"RLQEstAlg,omitempty"`
	ConversationalQualityR string `json:"conversationalQualityR,omitempty"`
	RCQEstAlg              string `json:"RCQEstAlg,omitempty"`
	ExternalRIn            string `json:"externalRIn,omitempty"`
	ExtRIEstAlg            string `json:"extRIEstAlg,omitempty"`
	ExternalROut           string `json:"externalROut,omitempty"`
	ExtROEstAlg            string `json:"extROEstAlg,omitempty"`
	MOSLQ                  string `json:"MOSLQ,omitempty"`
	MOSLQEstAlg            string `json:"MOSLQEstAlg,omitempty"`
	MOSCQ                  string `json:"MOSCQ,omitempty"`
	MOSCQEstAlg            string `json:"MOSCQEstAlg,omitempty"`
	QoEEstAlg              string `json:"QoEEstAlg,omitempty"`
}

// Parsing functions
func parseJitterBuffer(input string) JitterBuffer {
	jb := JitterBuffer{}
	parts := strings.Fields(input)
	for _, part := range parts {
		kv := strings.Split(part, "=")
		key, value := kv[0], kv[1]
		switch key {
		case "JBA":
			jb.Adaptive = value
		case "JBR":
			jb.Rate = value
		case "JBN":
			jb.Nominal = value
		case "JBM":
			jb.Max = value
		case "JBX":
			jb.AbsMax = value
		}
	}
	return jb
}

func parsePacketLoss(input string) PacketLoss {
	pl := PacketLoss{}
	parts := strings.Fields(input)
	for _, part := range parts {
		kv := strings.Split(part, "=")
		key, value := kv[0], kv[1]
		switch key {
		case "NLR":
			pl.NetworkPacketLossRate = value
		case "JDR":
			pl.JitterBufferDiscardRate = value
		}
	}
	return pl
}

func parseBurstGapLoss(input string) BurstGapLoss {
	bgl := BurstGapLoss{}
	parts := strings.Fields(input)
	for _, part := range parts {
		kv := strings.Split(part, "=")
		key, value := kv[0], kv[1]
		switch key {
		case "BLD":
			bgl.BurstLossDensity = value
		case "BD":
			bgl.BurstDuration = value
		case "GLD":
			bgl.GapLossDensity = value
		case "GD":
			bgl.GapDuration = value
		}
	}
	return bgl
}

func parseDelay(input string) Delay {
	d := Delay{}
	parts := strings.Fields(input)
	for _, part := range parts {
		kv := strings.Split(part, "=")
		key, value := kv[0], kv[1]
		switch key {
		case "RTD":
			d.RoundTrip = value
		case "ESD":
			d.EndSystem = value
		case "OWD":
			d.OneWay = value
		case "IAJ":
			d.InterArrivalJitter = value
		case "MAJ":
			d.MeanAbsoluteJitter = value
		}
	}
	return d
}

func parseQualityEst(input string) QualityEst {
	qe := QualityEst{}
	parts := strings.Fields(input)
	for _, part := range parts {
		kv := strings.Split(part, "=")
		key, value := kv[0], kv[1]
		switch key {
		case "RLQ":
			qe.ListeningQualityR = value
		case "RLQEstAlg":
			qe.RLQEstAlg = value
		case "RCQ":
			qe.ConversationalQualityR = value
		case "RCQEstAlg":
			qe.RCQEstAlg = value
		case "EXTRI":
			qe.ExternalRIn = value
		case "ExtRIEstAlg":
			qe.ExtRIEstAlg = value
		case "EXTRO":
			qe.ExternalROut = value
		case "ExtROEstAlg":
			qe.ExtROEstAlg = value
		case "MOSLQ":
			qe.MOSLQ = value
		case "MOSLQEstAlg":
			qe.MOSLQEstAlg = value
		case "MOSCQ":
			qe.MOSCQ = value
		case "MOSCQEstAlg":
			qe.MOSCQEstAlg = value
		case "QoEEstAlg":
			qe.QoEEstAlg = value
		}
	}
	return qe
}

func parseSessionDesc(line string) SessionDesc {
	desc := SessionDesc{}
	parts := strings.Fields(line) // Split the string by space

	// Iterate over parts and parse each key-value pair
	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			continue // skip if the part does not contain key and value
		}
		key, value := kv[0], kv[1]

		switch key {
		case "PT":
			desc.PayloadType = value
		case "PD":
			desc.PayloadDescription = value
		case "SR":
			desc.SampleRate = value
		case "FD":
			desc.FrameDuration = value
		case "FO":
			desc.FrameOctets = value
		case "FPP":
			desc.FramesPerPackets = value
		case "PLC":
			desc.PacketLossConcealment = value
		case "SSUP":
			desc.SilenceSuppressionState = value
		}
	}

	return desc
}

type VqExtra struct {
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
	Country   string  `json:"country,omitempty"`
	City      string  `json:"city,omitempty"`
	Region    string  `json:"region,omitempty"`
	Customer  string  `json:"customer,omitempty"` // look up using external API that we store for a period?
	System    string  `json:"system,omitempty"`   // look up using external API that we store for a period?
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
			metric.SessionDesc = parseSessionDesc(value)
		case "JitterBuffer":
			metric.JitterBuffer = parseJitterBuffer(value)
		case "PacketLoss":
			metric.PacketLoss = parsePacketLoss(value)
		case "BurstGapLoss":
			metric.BurstGapLoss = parseBurstGapLoss(value)
		case "Delay":
			metric.Delay = parseDelay(value)
		case "QualityEst":
			metric.QualityEst = parseQualityEst(value)
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
