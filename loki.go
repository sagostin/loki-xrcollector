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

	var region string
	if len(geoIpRecord.Subdivisions) > 0 {
		region = geoIpRecord.Subdivisions[0].Names["en"]
	} else if len(geoIpRecord.Subdivisions) > 1 {
		log.Warn("Sender has multiple subdivisions/regions: ", geoIpRecord.Subdivisions)
	}

	labels := map[string]string{
		"job":        "vqrtcpxr",
		"device":     device,
		"lan_addr":   lanAddr,
		"wan_addr":   ip.String(),
		"city":       geoIpRecord.City.Names["en"],
		"region":     region,
		"country":    geoIpRecord.Country.Names["en"],
		"user_agent": sipMsg.UserAgent,
		/*"lat": geoIpRecord.Location.Latitude,
		"long": geoIpRecord.Location.Longitude,
		"customer": "todo using connectwise",*/
	}

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
	VqReport      VqReport  `json:"vqReport,omitempty"` // this is the header for if it is an alert or call term type
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

type VqReport struct {
	Name       string `json:"name,omitempty"`
	ReportType string `json:"reportType,omitempty"`
	AlertType  string `json:"alertType,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Dir        string `json:"dir,omitempty"`
}

type SessionDesc struct {
	PayloadType             int64  `json:"payloadType,omitempty"`
	PayloadDescription      string `json:"payloadDescription,omitempty"`
	SampleRate              int64  `json:"sampleRate,omitempty"`
	FrameDuration           int64  `json:"frameDuration,omitempty"`
	FrameOctets             int64  `json:"frameOctets,omitempty"`
	FramesPerPackets        int64  `json:"framesPerPackets,omitempty"`
	PacketLossConcealment   int64  `json:"packetLossConcealment,omitempty"`
	SilenceSuppressionState string `json:"silenceSuppressionState,omitempty"`
}

type JitterBuffer struct {
	Adaptive int64 `json:"adaptive,omitempty"` // indicates the jitter buffer in the endpoint ("0" - unknown; "1" - reserved; "2" - non-adaptive; "3" - adaptive)
	Rate     int64 `json:"rate,omitempty"`
	Nominal  int64 `json:"nominal,omitempty"`
	Max      int64 `json:"max,omitempty"`
	AbsMax   int64 `json:"absMax,omitempty"`
}

type PacketLoss struct {
	NetworkPacketLossRate   float64 `json:"networkPacketLossRate,omitempty"`
	JitterBufferDiscardRate float64 `json:"jitterBufferDiscardRate,omitempty"`
}

type BurstGapLoss struct {
	BurstLossDensity float64 `json:"burstLossDensity,omitempty"`
	BurstDuration    int64   `json:"burstDuration,omitempty"`
	GapLossDensity   float64 `json:"gapLossDensity,omitempty"`
	GapDuration      int64   `json:"gapDuration,omitempty"`
	GapMin           int64   `json:"gapMin,omitempty"`
}

type Delay struct {
	RoundTrip          int64 `json:"roundTrip,omitempty"`
	EndSystem          int64 `json:"endSystem,omitempty"`
	OneWay             int64 `json:"oneWay,omitempty"`
	InterArrivalJitter int64 `json:"interArrivalJitter,omitempty"`
	MeanAbsoluteJitter int64 `json:"meanAbsoluteJitter,omitempty"`
}

type QualityEst struct {
	RListeningQuality      int64   `json:"rListeningQuality,omitempty"`
	RLQEstAlg              string  `json:"RLQEstAlg,omitempty"`
	RConversationalQuality int64   `json:"rConversationalQuality,omitempty"`
	RCQEstAlg              string  `json:"RCQEstAlg,omitempty"`
	ExternalRIn            int64   `json:"externalRIn,omitempty"`
	ExtRIEstAlg            string  `json:"extRIEstAlg,omitempty"`
	ExternalROut           int64   `json:"externalROut,omitempty"`
	ExtROEstAlg            string  `json:"extROEstAlg,omitempty"`
	MOSLQ                  float64 `json:"MOSLQ,omitempty"`
	MOSLQEstAlg            string  `json:"MOSLQEstAlg,omitempty"`
	MOSCQ                  float64 `json:"MOSCQ,omitempty"`
	MOSCQEstAlg            string  `json:"MOSCQEstAlg,omitempty"`
	QoEEstAlg              string  `json:"QoEEstAlg,omitempty"`
}

// Parsing functions
func parseVqReport(input string) VqReport {
	jb := VqReport{}

	if input == "CallTerm" {
		jb.ReportType = "CallTerm"
	} else {
		jb.ReportType = "Alert"
		parts := strings.Fields(input)
		for _, part := range parts {
			kv := strings.Split(part, "=")
			key, value := kv[0], kv[1]
			switch key {
			case "Type":
				jb.AlertType = value
			case "Severity":
				jb.Severity = value
			case "Dir":
				jb.Dir = value
			}
		}
	}
	return jb
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
			jb.Adaptive, _ = strconv.ParseInt(value, 10, 64)
		case "JBR":
			jb.Rate, _ = strconv.ParseInt(value, 10, 64)
		case "JBN":
			jb.Nominal, _ = strconv.ParseInt(value, 10, 64)
		case "JBM":
			jb.Max, _ = strconv.ParseInt(value, 10, 64)
		case "JBX":
			jb.AbsMax, _ = strconv.ParseInt(value, 10, 64)
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
			pl.NetworkPacketLossRate, _ = strconv.ParseFloat(value, 64)
		case "JDR":
			pl.JitterBufferDiscardRate, _ = strconv.ParseFloat(value, 64)
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
			bgl.BurstLossDensity, _ = strconv.ParseFloat(value, 64)
		case "BD":
			bgl.BurstDuration, _ = strconv.ParseInt(value, 10, 64)
		case "GLD":
			bgl.GapLossDensity, _ = strconv.ParseFloat(value, 64)
		case "GD":
			bgl.GapDuration, _ = strconv.ParseInt(value, 10, 64)
		case "GMIN":
			bgl.GapMin, _ = strconv.ParseInt(value, 10, 64)
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
			d.RoundTrip, _ = strconv.ParseInt(value, 10, 64)
		case "ESD":
			d.EndSystem, _ = strconv.ParseInt(value, 10, 64)
		case "OWD":
			d.OneWay, _ = strconv.ParseInt(value, 10, 64)
		case "IAJ":
			d.InterArrivalJitter, _ = strconv.ParseInt(value, 10, 64)
		case "MAJ":
			d.MeanAbsoluteJitter, _ = strconv.ParseInt(value, 10, 64)
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
			qe.RListeningQuality, _ = strconv.ParseInt(value, 10, 64)
		case "RLQEstAlg":
			qe.RLQEstAlg = value
		case "RCQ":
			qe.RConversationalQuality, _ = strconv.ParseInt(value, 10, 64)
		case "RCQEstAlg":
			qe.RCQEstAlg = value
		case "EXTRI":
			qe.ExternalRIn, _ = strconv.ParseInt(value, 10, 64)
		case "ExtRIEstAlg":
			qe.ExtRIEstAlg = value
		case "EXTRO":
			qe.ExternalROut, _ = strconv.ParseInt(value, 10, 64)
		case "ExtROEstAlg":
			qe.ExtROEstAlg = value
		case "MOSLQ":
			qe.MOSLQ, _ = strconv.ParseFloat(value, 64)
		case "MOSLQEstAlg":
			qe.MOSLQEstAlg = value
		case "MOSCQ":
			qe.MOSCQ, _ = strconv.ParseFloat(value, 64)
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
			desc.PayloadType, _ = strconv.ParseInt(value, 10, 64)
		case "PD":
			desc.PayloadDescription = value
		case "SR":
			desc.SampleRate, _ = strconv.ParseInt(value, 10, 64)
		case "FD":
			desc.FrameDuration, _ = strconv.ParseInt(value, 10, 64)
		case "FO":
			desc.FrameOctets, _ = strconv.ParseInt(value, 10, 64)
		case "FPP":
			desc.FramesPerPackets, _ = strconv.ParseInt(value, 10, 64)
		case "PLC":
			desc.PacketLossConcealment, _ = strconv.ParseInt(value, 10, 64)
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
				report := parseVqReport(vqReport)
				vqRtcpXr.VqReport = report

				// need to handle the CallTerm portion if doesn't contain VQ Alert Report???!??
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
