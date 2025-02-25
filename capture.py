from scapy.all import *
from datetime import datetime
import sys, argparse
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import TLSClientHello
import cryptography

load_layer("tls")
load_layer("http")
parser = argparse.ArgumentParser(prog='Capture', description='This program is used to sniff packets from a particular network interface.', allow_abbrev=False)

parser.add_argument('-i', nargs=1, help='Specifies network interface to sniff (eth0 by default)', metavar='interface')
parser.add_argument('-r', nargs=1, help='Specifies tracefile file path to read previously captured packets. Will be ignored if -i argument is specified.', metavar='tracefile')
parser.add_argument('expression', nargs='*', help='Specfies a BPF filter for monitoring a subset of traffic.')

print(sys.argv)
args=parser.parse_args()

def parse_packet(packet):
	
	if packet.haslayer(TCP) and packet.haslayer(TLS) and packet.haslayer(TLSClientHello):
		TLSCH = packet[TLSClientHello]
		time = str(datetime.fromtimestamp(float(packet.time)))
		if hasattr(TLSCH, "ext"):
            		for ext in TLSCH.ext:
            			if ext.type == 0:
            				dst_host = ext.servernames[0].servername.decode()
            				print(f"{time} TLS  {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} {dst_host}")
            				return
	if packet.haslayer(TCP) and packet.haslayer(Raw):
		time = str(datetime.fromtimestamp(float(packet.time)))
		content = TLS(packet.load)
		if content and content.haslayer(TLSClientHello): 
			TLSCH = content[TLSClientHello]
			if hasattr(TLSCH, "ext"):
				for ext in TLSCH.ext:
					if ext.type == 0:
						dst_host = ext.servernames[0].servername.decode()
						print(f"{time} TLS  {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} {dst_host}")
						return
					
		method = None
		content = packet[Raw].load.decode(errors='ignore').split(" ")
		if content[0]=="GET":
			method = "GET"
		elif content[0]=="POST":
			method = "POST"
		else:
			return
		print(f"{time} HTTP {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} {content[3][:-13]} {content[0]} {content[1]}")
		return
	if packet.haslayer(UDP) and packet.haslayer(DNSQR) and (packet[DNSQR].qtype == 1) and packet[DNS].qr == 0:
		time = str(datetime.fromtimestamp(float(packet.time)))
		domain = packet[DNSQR].qname.decode()
		print(f"{time} DNS  {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport} {domain}")
		
print(args)
if args.i != None:
	if args.expression != None:
		args.expression = " ".join(args.expression)
		print(args.expression)
	sniff(filter=args.expression, prn=parse_packet, iface=args.i[0])
elif args.i == None and args.r == None:
	if args.expression != None:
		args.expression = " ".join(args.expression)
		print(args.expression)
	sniff(filter=args.expression, prn=parse_packet, iface="eth0")
elif args.r != None:
	pcap = rdpcap(args.r[0])
	for packet in pcap:
		parse_packet(packet)
		
