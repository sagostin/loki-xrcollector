# heplify-xrcollector

Is a collector for SIP RTCP-XR voice quality reports and a HEP client.

### Installation

Download [heplify-xrcollector](https://github.com/negbie/heplify-xrcollector/releases) and execute 'chmod +x heplify-xrcollector'

### Usage

```bash
  -debug
        Log with debug level
  -hi uint
        HEP ID (default 3333)
  -hs string
        HEP UDP server address (default "127.0.0.1:9060")
  -xs string
        XR collector UDP listen address (default ":5060")
```

### Examples

```bash
# Listen on 0.0.0.0:5060 for vq-rtcpxr and send it as HEP to 127.0.0.1:9060
./heplify-xrcollector

# Listen on 0.0.0.0:9066 for vq-rtcpxr and send it as HEP to 192.168.1.10:9060
./heplify-xrcollector -xs :9066 -hs 192.168.1.10:9060

# Additionally change HEP ID to 1234 and log with debug level
./heplify-xrcollector -xs :9066 -hs 192.168.1.10:9060 -hi 1234 -debug

```
