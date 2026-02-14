from scapy.all import sniff, IP, TCP, UDP

def packet_handler(packet):
	if IP in packet:
		src = packet[IP].src
		dst = packet[IP].dst
		proto = packet[IP].proto
		
		if TCP in packet:
			print(f"[TCP] {src} -> {dst} | Port {packet[TCP].dport}")
		elif UDP in packet:
			print(f"[UDP] {src} -> {dst} | Port {packet[UDP].dport}")
		else:
			print(f"[IP] {src} -> {dst} | Proto {proto}")

sniff(prn=packet_handler, store=False)
