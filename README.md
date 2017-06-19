# SimpleTAP - OpenFlow TAP Aggregation App
SimpleTAP it's an SDN application for [Ryu SDN Controller](https://osrg.github.io/ryu/), which configures TAP Aggregation Fabric with OpenFlow switches.
## Installation
* Install Python (2.7 and 3.4+ is supported)
* Get App from Github: `git clone git://github.com/kvadrage/of-tap-aggregation.git && cd of-tap-aggregation`
* Install App prerequisites: `pip install -r requirements.txt`
## Usage
* Connect your TAP devices or SPAN ports to a fabric of switches with OpenFlow v1.3 support
* Connect your servers, running visibility and monitoring tools (like Wireshark or tcpdump), to this fabric as well
* Properly configure OpenFlow on these switches:
  - OpenFlow 1.3
  - Controller IP (port 6633)
  - No TLS encryption
* Define the App config in **config.json** file
  - Define OpenFlow **Datapath IDs (DPIDs)** for your switches in your fabric
  - Define your **TAP rules** configuration (see below)
  - Define your **TAP devices** configuration to automatically configure SPAN/Mirroring sessions on them. Supported device types:
    - Linux host/switch ([TC mirred](http://man7.org/linux/man-pages/man8/tc-mirred.8.html))
    - Mellanox switches with [MLNX-OS](http://www.mellanox.com/page/mlnx_os)
* Run the App: `./run.sh`
## App configuration file
App configuration is represented as a dictionary and loaded on start from JSON file  `config.json` and structured into three major sections:
* **switches** - defines switch DPIDs, that are allowed to participate in TAP Aggregation fabric
* **rules** - defines all TAP rules, that build end-to-end TAP sessions to deliver traffic from TAP devices to monitoring servers through entire fabric
  - only ingress switch (ingress port) and egress switch (egress port) are required to be defined
  - App will outomatically build the path the fabric and program OpenFlow rules end-to-end
* **taps** - defines active TAP devices, where automatic SPAN/Mirroring configuration is also required
### switches example
```json
"switches": {
  "0000000000000001": {
    "name": "s1"
  },
  "0000000000000002": {
    "name": "s2"
  },
  "0000000000000003": {
    "name": "s3"
  }
}
```
### rules example
```json
"rules": {
  "rule1": {
    "in_switch": "0000000000000001",
    "in_port": "s1-eth1",
    "out_switch": "0000000000000003",
    "out_port": "s3-eth2"
  },
  "rule2": {
    "in_switch": "0000000000000001",
    "in_port": "s1-eth2",
    "out_switch": "0000000000000003",
    "out_port": "s3-eth2",
    "span": {
      "tap": "tap1",
      "in_port": "1/20",
      "out_port": "1/21",
      "direction": "both",
      "truncate": false
    }
  }
}
```
### taps example
```json
"taps": {
  "tap1": {
    "device_type": "mellanox",
    "hostname": "10.0.0.11",
    "username": "admin",
    "password": "admin"
  }
}
```
## OpenFlow Pipeline
TAP rules are translated into the following OpenFlow pipeline:
* Only table 0 is supported
* Match: based on **in_port**
* Action: output **out_port**
* End-to-end path is being provisioned using shortest path algorithm
* There is a chance that traffic from different TAP sessions might be mixed in the fabric
## Example topology
TBD
