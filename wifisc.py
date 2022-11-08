from scapy.all import *
import sys
import signal
import os

# terminate during script using ctrl + C

def Terminate_signal(signal, frame):
    print("\n script gestopt door gebruiker!")
    os.system("kill -9" + str(os.getpid()))
    sys.exit(1)    

def exitscript(signal, exitframe):
    print("signal exit")
    sys.exit(1)

def howToUse():
    if len(sys.argv) < 3:
        print("foute syntax use:")
        print("scapy.py -i <interface>\n")
        sys.exit(1)

def packetsniffer(packet):
    try:
        SRCMAC = packet[0].addr2
        DSTMAC = packet[0].addr1
        BSSID = packet[0].addr3
    except:
        print("geen juist mac address beschikbaar")
       
        sys.exc_clear()

    try:
        SSIDSize = packet[0][scapy.layers.dot11.dot11Elt].len
        SSID = packet[0][scapy.layers.dot11.dot11Elt].info
    except:
        SSID = ""
        SSIDSize = 0
    #check voor Beacon frame (type = 0, subtype =8)
    if packet[0].type == 0:
        ST = packet[0][scapy.layers.dot11].subtype
        if str(ST) == "8" and SSID != "" and DSTMAC.lower() == "ff:ff:ff:ff:ff:ff":
            pakketje = packet[scapy.layers.Dot11Elt]
            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%"
                                "Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
            channel = None
            crypto = set()

    # track SSID's
def init_proces ():
    global ssid_list
    ssid_list = {}
    global s
    s = conf.L2socket(iface=newiface)

#setup wireless if in monitor mode
def setup_monitor (iface):
    os.system('ifconfig ' + iface + ' down')
    try:
        os.system('iwconfig '+ iface +' mode monitor')
    except:
        print("setup failed try again")
        sys.exit(1)
    os.system('ifconfig ' + iface + ' up')

# Main

if __name__ == "__main__":
    signal.signal(signal.SIGINT, Terminate_signal)
    howToUse()
    parameters = {sys.argv[1]:sys.argv[2]}
    if "mon" not in str(parameters["-i"]):
        newiface = setup_monitor(parameters["-i"])
    else:
        newiface = str(parameters["-i"])
    init_proces()
    print("sniffing on interface" + str(newiface))
    sniff(iface=newiface, prn=packetsniffer, store =0)
