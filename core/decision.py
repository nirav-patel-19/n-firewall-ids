import time
import netifaces

class DecisionEngine:
	def __init__(self):
		# Memory to track how many times an IP has triggered an alert
		# { 'ip': {'count': 0, 'last_action': 'ALLOW'} }
		self.ip_history = {}
		self.ESCALATION_THRESHOLD = 3
		self.local_ip = self.get_local_ip()

		print(f"[DecisionEngine] Monitoring Host IP detected as: {self.local_ip}")

	def get_local_ip(self):
		"""Detects the real IP address from the active network interface.
		   Avoids default ip problems.
		"""
		for iface in netifaces.interfaces():
			if iface == "lo":
				continue

			addrs = netifaces.ifaddresses(iface)
			if netifaces.AF_INET in addrs:
				for addr in addrs[netifaces.AF_INET]:
					ip = addr.get('addr')
					if ip and not ip.startswith("127."):
						return ip
		return None

	def decide(self, packet_data, firewall_allowed, ids_alert):
		"""
		The Correlation Brain.
		Combines Firewall (Policy) + IDS (Behavior) outputs.
		"""
		src_ip = packet_data['src_ip']
		final_action = "ALLOW"
		severity = "INFO"
		reason = "Normal Traffic"

		if src_ip == self.local_ip:
			return {
				"timestamp": time.time(),
				"src_ip": src_ip,
				"dst_ip": packet_data['dst_ip'],
				"proto": packet_data['proto'],
				"fw_decision": "ALLOW",
				"ids_alert": None,
				"final_action": "ALLOW",
				"severity": "INFO",
				"reason": "Local System Traffic"
			}
                
		# 1. Initialize hitory for new IP
		if src_ip not in self.ip_history:
			self.ip_history[src_ip] = {'alert_count': 0}

		# --- CORRELATION RULES ---

		# RULE 1: Policy Override
		# If firewall says BLOCK, we always DROP.
		if not firewall_allowed:
			final_action = "DROP"
			severity = "LOW"
			reason = "Firewall Policy Violation"

		# RULE 2: Behavioral Override (The Detective's Input)
		if ids_alert:
			self.ip_history[src_ip]['alert_count'] += 1

			if ids_alert['severity'] in ['HIGH', 'CRITICAL']:
				final_action = "DROP"
				severity = ids_alert['severity']
				reason = f"Suspicious Activity: {ids_alert['type']}"

		# RULE 3: Escalation (Repeated Offender)
		if self.ip_history[src_ip]['alert_count'] >= self.ESCALATION_THRESHOLD:
			final_action = "BLOCK_IP"
			severity = "CRITICAL"
			reason = f"Repeated Attacks ({self.ip_history[src_ip]['alert_count']} alerts)"

		# 2. Construct the Unified Event Object
		unified_event = {
			"timestamp": time.time(),
			"src_ip": src_ip,
			"dst_ip": packet_data['dst_ip'],
			"proto": packet_data['proto'],
			"fw_decision": "ALLOW" if firewall_allowed else "BLOCK",
			"ids_alert": ids_alert['type'] if ids_alert else None,
			"final_action": final_action,
			"severity": severity,
			"reason": reason
		}

		return unified_event
