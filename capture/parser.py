from scapy.layers.inet import IP, UDP, TCP, ICMP

def parse_packet(packet):
	"""
	Stage 2: Robust Normalization.
	Return None if the packet is not a n IP packet.
	"""

	if not packet.haslayer(IP):
		return None
	
	try:
		parsed_data = {
			"src_ip": packet[IP].src,
			"dst_ip": packet[IP].dst,
			"proto": "OTHER",
			"src_port": 0,
			"dst_port": 0,
			"payload_length": len(packet[IP].payload),
			"flags": None
		}

		if packet.haslayer(TCP):
			parsed_data["proto"] = "TCP"
			parsed_data["src_port"] = packet[TCP].sport
			parsed_data["dst_port"] = packet[TCP].dport
			parsed_data["flags"] = packet[TCP].flags
		elif packet.haslayer(UDP):
			parsed_data["proto"] = "UDP"
			parsed_data["src_port"] = packet[UDP].sport
			parsed_data["dst_port"] = packet[UDP].dport
		elif packet.haslayer(ICMP):
			parsed_data["proto"] = "ICMP"
	
		return parsed_data
	
	except Exception as e:
		return None
