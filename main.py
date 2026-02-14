import threading
import signal
import sys
from queue import Empty
from capture.sniffer_v2 import packet_buffer, start_ingestion
from capture.parser import parse_packet
from capture.control import shutdown_event
from rules.engine import check_rules
from ids.detection import IDSEngine
from core.decision import DecisionEngine
from rules.engine import add_block_rule

# --- ANSI COLORS FOR VISUALIZATION ---
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLINK = "\033[5m"
RESET = "\033[0m"

# --- SHUTDOWN ---
def shutdown_handler(sig, frame):
	"""
	Catches Ctrl+C. This is vital so the background sniffer thread doesn't beacome a 'Zombie' process.
	"""

	print("\n[!] Graceful Shutdown Initialized...")
	print(f"[*] Packets remaining in buffer: {packet_buffer.qsize()}")
	print("[*] Closing Firewall. Goodbye!")
	shutdown_event.set()
	sys.exit(0)

# Register the signal with the Linux OS
signal.signal(signal.SIGINT, shutdown_handler)

# --- STAGE 2: PROCESSING ENGINE ---
def start_processing():
	print("[*] Stage 2: Parser is now watching the buffer...")
	print("[*] Stage 3: Firewall Rules Engine is active...")
	print("[*] Stage 4: IDS Behaviour Engine is initialized...")
	print("[*] Stage 5: Correlation Brain is initialized...")

	ids = IDSEngine()
	brain = DecisionEngine() # Brain
	try:
		while not shutdown_event.is_set():
			if not packet_buffer.empty():
				# 1. Pull from Stage 1
				try:
					raw_pkt = packet_buffer.get(timeout=1)
				except Empty:
					continue
				
				# 2. Run through Stage 2
				clean_pkt = parse_packet(raw_pkt)
				
				if clean_pkt and 'dst_ip' in clean_pkt:
					try:
						
						# 3. Firewall Decision (Policy)
						fw_allowed = check_rules(clean_pkt)
						
						# 4. IDS Dectection (Behaviour)
						# We run this BEFORE printing so we can show alerts alongside traffic
						ids_alert = ids.detect(clean_pkt)
						
						# 5. Correlation & Decision
						# We pass the results of Stg 3 & 4 into Stg 5
						event = brain.decide(clean_pkt, fw_allowed, ids_alert)

						# --- VISUALIZATION LOGIC ---
						color = GREEN
						if event['final_action'] == "DROP":
							color = RED
						elif event['final_action'] == "BLOCK_IP":
							color = RED + BLINK
						elif event['final_action'] == "ALERT_ONLY":
							color = YELLOW
						
						print(f"{color}[{event['final_action']}]{RESET} {event['reason']} | {event['proto']} | {event['src_ip']} -> {event['dst_ip']}")
						
						if event['final_action'] == "BLOCK_IP":
							if add_block_rule(event['src_ip']):
								print(f"\t{RED}[ACTION] Offender {event['src_ip']} added to blacklist.{RESET}")

					except KeyError as e:
						print(f"[!] Error: Missing field {e} in packet data.")
				
				# Mark task as done
				packet_buffer.task_done()

	except Exception as e:
		print(f"[!] Processing Error: {e}")



if __name__ == "__main__":
	# Start Stage 1 in background
	#daemon=True ensures this thread dies when the main thread dies
	sniffer_thread = threading.Thread(target=start_ingestion, daemon=True)
	sniffer_thread.start()
	
	start_processing()
