# loki-xrcollector

Is a collector for SIP RTCP-XR voice quality reports, then sends them over to a Loki server. It is designed to allow messages using only TLS.

This is a fork of the heplify-xrcollector.

### Installation

Generate certificates

```
openssl req -x509 -newkey rsa:4096 -keyout server_enc.key -out server.crt -sha256 -days 365
then
openssl rsa -in server_enc.key -out server.key
```

Build this repository from source.

Setup system service and include Loki information.

Run and wait for traffic.

### Usage

```bash
-debug
        Log with debug level
-xs string
        XR collector UDP listen address (default ":7060")
-lokiURL string
        Loki URL
-lokiUser string
        Loki Basic Auth Username
-lokiPass string
        Loki Basic Auth Password
```

