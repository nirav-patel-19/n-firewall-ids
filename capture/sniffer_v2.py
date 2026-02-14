import threading
from scapy.all import sniff, conf
from queue import Queue
from capture.control import shutdown_event

packet_buffer = Queue(maxsize=2000)

def handle_packet(packet):
        """
        Callback function: Executed for every packet detected on the wire.
        """
        try:
                #Put the raw packet into the buffer for stage 2 to pick up
                #block=False ensures the sniffer never 'waits' if the buffer is full
                packet_buffer.put(packet, block=False)
                print("Packet Captures.")
        except:
                #In a real firewall, a full buffer means we are being overwhelmed
                pass

def start_ingestion(interface=None):
	#If no interface is provided use the system default
	if interface is None:
		interface = conf.iface

	"""
        Starts the Scapy sniffer in a way that doesn't hoard memory.
        """

	print(f"[+] Stage 1: Ingestion Layer active on {interface}...")

        #store=0 is critical for M.Tech/Production
        #It tells Scapy NOT to keep packets in memory after the callback finishes.
	try:
		sniff(iface=interface, prn=handle_packet, store=0, stop_filter=lambda _: shutdown_event.is_set())
	except PermissionError:
		print("[!] Error: You should run this script with sudo!")
	except Exception as e:
		print(f"[!] Scapy Error: {e}")

if __name__ == "__main__":
        #For standlone testing
        start_ingestion()
