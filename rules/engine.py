import json
import os
import json

# Get the absoulte path to the JSON file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "firewall_rules.json")

def _save_rules_atomic(rules):
	"""
	Safely write rules so IDS and Dashboard never read a half-written file.
	"""
	temp_file = RULES_FILE + ".tmp"

	with open(temp_file, "w") as f:
		json.dump(rules, f, indent=4)

	# Atomic replace (Linux safe swap)
	os.replace(temp_file, RULES_FILE)


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
	rules = load_rules()

	if "blocked_ips" not in rules:
		rules["blocked_ips"] = []

	if ip_to_block in rules["blocked_ips"]:
		print(f"[Rules] {ip_to_block} already blocked.")
		return True

	rules["blocked_ips"].append(ip_to_block)

	try:
		_save_rules_atomic(rules)
		print(f"[Rules] Added {ip_to_block}")
		return True
	except Exception as e:
		print(f"[!] Failed saving rules:", e)
		return False

def remove_block_rule(ip_to_remove):
	rules = load_rules()

	blocked = rules.get("blocked_ips", [])

	if ip_to_remove not in blocked:
		print(f"[Rules] {ip_to_remove} not found.")
		return True   # treat as already removed

	blocked.remove(ip_to_remove)
	rules["blocked_ips"] = blocked

	try:
		_save_rules_atomic(rules)
		print(f"[Rules] Removed {ip_to_remove}")
		return True
	except Exception as e:
		print(f"[!] Failed saving rules:", e)
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
