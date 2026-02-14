import time

class IDSEngine:
	def __init__(self):
		# This dicitonary stores the "Memory" of the IDS
		# Format: {'src_ip': { 'ports': set(), 'start_time': timestamp, 'icmp_count': 0 } }
		self.state = {}
		
		# Configuration (Thresholds)
		self.WINDOW_SIZE = 5.0          # Time window in seconds
		self.PORT_SCAN_LIMIT = 5        # Alert if > 5 distinct ports hit
		self.ICMP_FLOOD_LIMIT = 10      # Alert if > 10 pings sent
		self.SYN_FLOOD_LIMIT = 20
	
	def detect(self, packet):
		"""
		Analyzes the packet for behaviour anomalies.
		Returns an Alert Dictionary if an attack is detected, else None.
		"""
		src_ip = packet.get('src_ip')
		dst_ip = packet.get('dst_ip')
		current_time = time.time()

		# --- 1. MALFORMED PACKET DETECTION (Stateless) ---

		# A. Land Attack: Source IP is same as Destination IP
		if src_ip == dst_ip:
			return {
				"type": "MALFORMED_PACKET",
				"src_ip": src_ip,
				"severity": "CRITICAL",
				"details": "Land Attack (Src=Dst)"
			}

		# --- 2. STATEFUL DETECTION (Requires Memory) ---
		# Initialize state for new IPs
		if src_ip not in self.state:
			self.state[src_ip] = {
				'ports': set(),
				'icmp_count': 0,
				'syn_count': 0,
				'start_time': current_time
			}
		
		# Get the tracking data for this IP
		tracker = self.state[src_ip]
		
		# 1. RESET WINDOW: If time window expired, clear the memory for this IP
		if current_time - tracker['start_time'] > self.WINDOW_SIZE:
			tracker['ports'] = set()
			tracker['icmp_count'] = 0
			tracker['syn_count'] = 0
			tracker['start_time'] = current_time
		
		# Detection Logic
		# B) SYN FLOOD DETECTION
		# Check if it is TCP and has the SYN flag ONLY (S)
		if packet['proto'] == 'TCP' and packet['flags'] == 'S':
			tracker['syn_count'] += 1
			if tracker['syn_count'] > self.SYN_FLOOD_LIMIT:
				return {
					"type": "SYN_FLOOD",
					"src_ip": src_ip,
					"severity": "High",
					"details": f"Sent {tracker['syn_count']} SYN packets"
				}

		# C) PORT SCAN DECTECTION (TCP/UDP)
		if packet['proto'] in ['TCP', 'UDP']:
			dst_port = packet['dst_port']
			tracker['ports'].add(dst_port)
			
			if len(tracker['ports']) > self.PORT_SCAN_LIMIT:
				return {
				"type": "PORT_SCAN",
				"src_ip": src_ip,
				"severity": "HIGH",
				"details": f"Scanned {len(tracker['ports'])} ports"
				}
		
		# D) ICMP FLOOD DETECTION
		if packet['proto'] == 'ICMP':
			tracker['icmp_count'] += 1
			
			if tracker['icmp_count'] > self.ICMP_FLOOD_LIMIT:
				return {
				"type": "ICMP_FLOOD",
				"src_ip":src_ip,
				"severity": "MEDIUM",
				"details": f"Sent {tracker['icmp_count']} pings"
				}
		
		return None
