import json
import os
import json

# Get the absoulte path to the JSON file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "firewall_rules.json")

def load_rules():
	"""
	Loads rules from the JSON file.
	Returns a default empty rule set if the file is missing or broken.
	"""
	
	try:
		with open(RULES_FILE, "r") as f:
			return json.load(f)
	except Exception as e:
		print(f"[!] Error loading firewall rules: {e}")
		return {"blocked_ips": [], "blocked_ports": [], "blocked_protocols": []}

def add_block_rule(ip_to_block):
	"""
	Stage 5 Tool: Adds am IP to the blocklist in the JSON file.
	This makes the IDS decision persistent.
	"""
	rules = load_rules()

	# Ensure the key exists in the dictionary
	if 'blocked_ips' not in rules:
		rules['blocked_ips'] = []

	# Only add if the IP isn't already blocked to prevent duplicates
	if ip_to_block not in rules['blocked_ips']:
		rules['blocked_ips'].append(ip_to_block)

		try:
			with open(RULES_FILE, "w") as f:
				json.dump(rules, f, indent=4)
			return True
		except Exception as e:
			print(f"[!] Error writing to rules file: {e}")
			return False
	return False

def check_rules(packet_data):
	"""
	Input: The normalized packet dictionary from Stage 2.
	Output: True (Pass) or False (Block).
	"""
	
	rules = load_rules()
	
	# 1. Check Source IP
	if packet_data.get('src_ip') in rules.get('blocked_ips', []):
		return False
	
	# 2. Check Destination Port
	if packet_data.get('dst_port') in rules.get('blocked_ports', []):
		return False
	
	# 3. Check Protocol
	if packet_data.get('proto') in rules.get('blocked_protocols', []):
		return False
	
	return True
