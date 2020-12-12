from scapy.all import *
import argparse
import sys

dns_dict = {}

# Creates a dictionary of DNS Responses and the IPs resolved to
def dns_count(pkt):
	if pkt.haslayer(DNSRR):
		rrname = pkt.getlayer(DNSRR).rrname.decode("utf-8")
		rdata = pkt.getlayer(DNSRR).rdata
		dns_type = pkt.getlayer(DNSRR).type

		# Type 1: A record Type 28: AAAA record
		if dns_type == 1 or dns_type == 28:

			if not rrname in dns_dict:
				dns_dict[rrname] = []
			
			if not rdata in dns_dict[rrname]:
				dns_dict[rrname].append(rdata)


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", dest="pcap", help="Specify the path to the PCAP file to analyse")

	if len(sys.argv) != 3:
		parser.print_help(sys.stderr)
		sys.exit(1)

	args = parser.parse_args()
	pcap = args.pcap
	pkts = rdpcap(pcap)

	for pkt in pkts:
		dns_count(pkt)

	for item in dns_dict:
		print(f"[+] [{item}] has {len(dns_dict[item])} unique IP address(es)")


if __name__ == "__main__":
	main()