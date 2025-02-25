# Capture

**Capture** is a Python program that detects and prints HTTP requests, TLS Client Hello connections, and DNS requests over a specified interface, **regardless of port number**. Users have the option of also inputting a BPF filter for monitoring a subset of network traffic. For previously obtained captures, users also have the option of reading packets from a PCAP file (in tcpdump format).

## Dependencies

The only external dependency this program relies on is `scapy`, which can be installed using the following PowerShell command on Linux if not already pre-installed:

```
sudo apt install python3-scapy
```
## Commands

Here is an overview of the CLI commands.

positional arguments:
  expression    Specfies a BPF filter for monitoring a subset of traffic.

options:
  -h, --help    show this help message and exit
  -i interface  Specifies network interface to sniff (eth0 by default)
  -r tracefile  Specifies tracefile file path to read previously captured packets. Will be ignored if -i argument is specified.
  
**NOTE:** The order of CLI options are not important.
  
## Example Input and Output

1. HTTP and DNS Request to example.com over interface "eth0"
```
$ sudo python capture.py
2025-02-24 18:21:44.572134 DNS  10.0.2.15:46926 -> 10.0.2.3:53 example.com.
2025-02-24 18:21:56.591811 HTTP 10.0.2.15:38614 -> 23.215.0.136:80 example.com GET /favicon.ico
```
2. TLS and DNS Request to cs.stonybrook.edu over interface "eth0"
```
$ sudo python capture.py
2025-02-24 18:24:12.069474 DNS  10.0.2.15:48164 -> 10.0.2.3:53 www.cs.stonybrook.edu.
2025-02-24 18:24:12.232095 TLS  10.0.2.15:60528 -> 23.185.0.4:443 www.cs.stonybrook.edu
2025-02-24 18:24:17.771139 DNS  10.0.2.15:41014 -> 10.0.2.3:53 www.googletagmanager.com.
2025-02-24 18:24:17.824782 DNS  10.0.2.15:58257 -> 10.0.2.3:53 stackpath.bootstrapcdn.com.
2025-02-24 18:24:17.846619 DNS  10.0.2.15:43775 -> 10.0.2.3:53 fonts.googleapis.com.
2025-02-24 18:24:17.850213 DNS  10.0.2.15:41974 -> 10.0.2.3:53 use.typekit.net.
2025-02-24 18:24:17.867640 DNS  10.0.2.15:43123 -> 10.0.2.3:53 analytics.silktide.com.
2025-02-24 18:24:17.870054 DNS  10.0.2.15:49994 -> 10.0.2.3:53 cdn.jsdelivr.net.
2025-02-24 18:24:17.993050 TLS  10.0.2.15:56044 -> 23.223.209.67:443 use.typekit.net
2025-02-24 18:24:18.033250 TLS  10.0.2.15:36900 -> 3.168.122.93:443 analytics.silktide.com
2025-02-24 18:24:18.460585 DNS  10.0.2.15:38792 -> 10.0.2.3:53 p.typekit.net.
2025-02-24 18:24:18.914397 DNS  10.0.2.15:43129 -> 10.0.2.3:53 www.stonybrook.edu.
2025-02-24 18:24:18.979998 TLS  10.0.2.15:48108 -> 104.18.32.123:443 www.stonybrook.edu
2025-02-24 18:24:19.068732 TLS  10.0.2.15:56056 -> 23.223.209.67:443 use.typekit.net
2025-02-24 18:24:24.482098 DNS  10.0.2.15:58301 -> 10.0.2.3:53 www.google-analytics.com.

```

3. 
