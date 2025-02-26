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

1. Detecting HTTP and DNS (request) packets when connecting to example.com over interface "eth0".
```
$ sudo python capture.py
2025-02-24 18:21:44.572134 DNS  10.0.2.15:46926 -> 10.0.2.3:53 example.com.
2025-02-24 18:21:56.591811 HTTP 10.0.2.15:38614 -> 23.215.0.136:80 example.com GET /favicon.ico
```
2. Detecing TLS and DNS (request) packets when connecting to cs.stonybrook.edu over interface "eth0".
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

3. Reading a PCAP file (tcpdump format) produced by Wireshark that captured packets sniffed when connecting to example.com and then cs.stonybrook.edu.
```
$ sudo python capture.py -r test.pcap
2025-02-25 18:28:58.715276 DNS  10.0.2.15:40730 -> 10.0.2.3:53 example.com.
2025-02-25 18:28:59.009372 DNS  10.0.2.15:35465 -> 10.0.2.3:53 www.google-analytics.com.
2025-02-25 18:28:59.171720 HTTP 10.0.2.15:52852 -> 23.192.228.84:80 example.com GET /favicon.ico
2025-02-25 18:29:05.317745 DNS  10.0.2.15:46270 -> 10.0.2.3:53 www.cs.stonybrook.edu.
2025-02-25 18:29:05.389044 TLS  10.0.2.15:59624 -> 23.185.0.4:443 www.cs.stonybrook.edu
2025-02-25 18:29:07.214523 DNS  10.0.2.15:39157 -> 10.0.2.3:53 www.googletagmanager.com.
2025-02-25 18:29:07.485132 DNS  10.0.2.15:57436 -> 10.0.2.3:53 stackpath.bootstrapcdn.com.
2025-02-25 18:29:07.499036 DNS  10.0.2.15:58175 -> 10.0.2.3:53 fonts.googleapis.com.
2025-02-25 18:29:07.499903 DNS  10.0.2.15:44195 -> 10.0.2.3:53 use.typekit.net.
2025-02-25 18:29:07.500072 DNS  10.0.2.15:57316 -> 10.0.2.3:53 analytics.silktide.com.
2025-02-25 18:29:07.505427 DNS  10.0.2.15:35600 -> 10.0.2.3:53 cdn.jsdelivr.net.
2025-02-25 18:29:07.524917 TLS  10.0.2.15:33492 -> 18.67.65.65:443 analytics.silktide.com
2025-02-25 18:29:07.526701 TLS  10.0.2.15:50338 -> 104.18.10.207:443 stackpath.bootstrapcdn.com
2025-02-25 18:29:07.527630 TLS  10.0.2.15:36724 -> 104.18.187.31:443 cdn.jsdelivr.net
2025-02-25 18:29:07.541841 TLS  10.0.2.15:43444 -> 23.215.0.137:443 use.typekit.net
2025-02-25 18:29:07.828877 DNS  10.0.2.15:32798 -> 10.0.2.3:53 safebrowsing.googleapis.com.
2025-02-25 18:29:07.856772 DNS  10.0.2.15:34694 -> 10.0.2.3:53 p.typekit.net.
2025-02-25 18:29:07.871842 TLS  10.0.2.15:36558 -> 142.251.16.95:443 safebrowsing.googleapis.com
2025-02-25 18:29:07.896301 TLS  10.0.2.15:37766 -> 23.215.0.136:443 p.typekit.net
2025-02-25 18:29:08.052196 DNS  10.0.2.15:52055 -> 10.0.2.3:53 www.stonybrook.edu.
2025-02-25 18:29:08.074490 TLS  10.0.2.15:59010 -> 104.18.32.123:443 www.stonybrook.edu
2025-02-25 18:29:08.387736 TLS  10.0.2.15:50348 -> 104.18.10.207:443 stackpath.bootstrapcdn.com
```

4. Reading TLS requests on non-standard ports. To detect TLS Client Hello packets, a local server was created using `openssl` and self-certification. A connection was established using HTTPS. (NOTE: there is no SNI)

```
$ sudo python capture.py -i lo
2025-02-25 19:27:23.969481 TLS  ::1:58956 -> ::1:8443
2025-02-25 19:27:23.969486 TLS  ::1:58956 -> ::1:8443
```

5. Reading HTTP requests on non-standard ports by using the same server above but using HTTP to establish a connection.

```
$ sudo python capture.py -i lo
2025-02-25 19:34:23.179532 HTTP ::1:37456 -> ::1:8443 localhost:8443 GET /
2025-02-25 19:34:23.179543 HTTP ::1:37456 -> ::1:8443 localhost:8443 GET /
```
