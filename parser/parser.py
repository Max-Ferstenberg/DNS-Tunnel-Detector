#parser.py
# Module for extracting DNS query data from pcap files
# --------------------------------------------------------------------------------
# Module for extracting DNS query data from PCAP files
# Live capture is in detector/live.py and reuses the record format defined here.
#
# External dependencies:
# - scapy: https://scapy.readthedocks.io/en/latest/
#
# There are two main functions:
#   extract_subdomain(queryname, numlabels) -> (subdomain, parentdomain)
#   parse_pcap(filepath) -> list[dict]
#
# Each returned record is a dictionary with five fields:
#  - timestamp: float, the time the query was captured
#  - query_name: str, the full domain name queried
#  - subdomain: str, the subdomain part of the query (empty if none
#  - parent_domain: str, the parent domain (e.g. example.com)
#  - record_type: str, the DNS record type (e.g. "A", "MX", "TXT")
#
# Usage:
#   python parser.py <pcap_file>
# --------------------------------------------------------------------------------

# rdpcap reads a pcap file and returns a PacketList object.
# https://scapy.readthedocs.io/en/latest/api/scapy.utils.html#scapy.utils.rdpcap
from scapy.utils import rdpcap

# DNS and DNSQR are the layers in scapy that represent DNS packets and DNS query records respectively
# https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html
from scapy.layers.dns import DNS, DNSQR

#DNS record type integers mapped to readable strings; scapy stores record types as numbers internally
RECORD_TYPES = {
    1: "A", #IPv4 address
    2: "NS", #Name Server
    5: "CNAME", #Canonical Name
    6: "SOA", #Start of Authority
    10: "NULL", #Null record, used for testing and debugging
    12: "PTR", #Pointer record, used for reverse DNS lookups
    15: "MX", #Mail Exchange record, used to specify mail servers for a domain
    16: "TXT", #Text record, used to store arbitrary text data associated with a domain
    28: "AAAA", #IPv6 address
    33: "SRV", #Service locator, used to define the location of servers for specified services
    255: "ANY" #Wildcard record, matches any record type
}

def extract_subdomain(queryname, numlabels=2):
    # Given a full domain name, split it into subdomain and parent domain.
    # For example, with numlabels=2:
    # - "www.example.com" -> subdomain="www", parentdomain="example.com"
    # - "example.com" -> subdomain="", parentdomain="example.com"
    parts = queryname.split('.') # Split the domain name into parts by the dot separator
    if len(parts) <= numlabels:
        return "", queryname # If there are not enough parts, treat the whole name as the parent domain
    
    parentdomain = '.'.join(parts[-numlabels:]) # Join the last numlabels parts to form the parent domain
    subdomain = '.'.join(parts[:-numlabels]) # Join the remaining parts to form the subdomain
    return subdomain, parentdomain 

def parse_pcap(filepath):
    # Read the pcap file and extract DNS query records.
    # Each record is returned as a dictionary with timestamp, query_name, subdomain, parent_domain, and record_type.
    packets = rdpcap(filepath) # Read the pcap file and return a list of packets
    dns_queries = []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  #Check if it's a DNS query
            queryname = pkt[DNSQR].qname.decode('latin-1').rstrip('.') #iodine uses latin-1 encoding for domain names to preserve all byte values
            qtype = pkt[DNSQR].qtype #Get the DNS record type as an integer
            qtype_str = RECORD_TYPES.get(qtype, f"Unknown ({qtype})") #Convert the record type to a readable string, or label it as unknown if it's not in the mapping
            subdomain, parentdomain = extract_subdomain(queryname)

            #Build a dict
            record = {
                "timestamp": float(pkt.time), 
                "query_name": queryname, 
                "subdomain": subdomain,
                "parent_domain": parentdomain,
                "record_type": qtype_str,
            }
            dns_queries.append(record)

    return dns_queries

if __name__ == "__main__":
    # Used only for independent module testing, see usage above
    import sys
    if len(sys.argv) != 2:
        print("Usage: python parser.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    queries = parse_pcap(pcap_file)

    #Loop over dicts, access fields by key
    for record in queries:
        print(
            f"Subdomain: {record['subdomain']}, "
            f"Parent Domain: {record['parent_domain']}, "
            f"Record Type: {record['record_type']}"
        )