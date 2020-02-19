import dpkt, socket, sys

THRESHOLD = 3

def tcpFlags(tcp):
    ret = list()

    if tcp.flags & dpkt.tcp.TH_FIN != 0:
        ret.append('FIN')
    if tcp.flags & dpkt.tcp.TH_SYN  != 0:
        ret.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST  != 0:
        ret.append('RST')
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
        ret.append('PSH')
    if tcp.flags & dpkt.tcp.TH_ACK  != 0:
        ret.append('ACK')
    if tcp.flags & dpkt.tcp.TH_URG  != 0:
        ret.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE  != 0:
        ret.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR  != 0:
        ret.append('CWR')
    
    return ret


def compare_IPs(ip1, ip2):
    return sum(map(int, ip1.split('.'))) - sum(map(int, ip2.split('.')))

f = open('example.pcap')
pcap = dpkt.pcap.Reader(f)
print(pcap)

# suspect's IP: {# SYNs, # SYN-ACKs}
suspects = dict()
curPacket = 0

# Analyze captured packets.
for ts, buf in pcap:
    curPacket += 1

    eth = dpkt.ethernet.Ethernet(buf)

    # must be IP packets
    ip = eth.data
    if not ip:
        continue

    # skip non TCP
    tcp = ip.data
    if type(tcp) != dpkt.tcp.TCP:
        continue

    # Get all of the set flags in this TCP packet
    tcpFlag = tcpFlags(tcp)

    srcIP = socket.inet_ntoa(ip.src)
    dstIP = socket.inet_ntoa(ip.dst)

    # add suspicious IP to list
    if {'SYN'} == set(tcpFlag):
        if srcIP not in suspects: suspects[srcIP] = {'SYN': 0, 'SYN-ACK': 0}
        suspects[srcIP]['SYN'] += 1
    elif {'SYN', 'ACK'} == set(tcpFlag):
        if dstIP not in suspects: suspects[dstIP] = {'SYN': 0, 'SYN-ACK': 0}
        suspects[dstIP]['SYN-ACK'] += 1

# remove suspected IP that isn't 3 times the syn/syn ack
for s in suspects.keys():
    if suspects[s]['SYN'] < (suspects[s]['SYN-ACK'] * THRESHOLD):
        del suspects[s]


for s in sorted(suspects.keys(), cmp=compare_IPs):
    syns = suspects[s]['SYN']
    synacks = suspects[s]['SYN-ACK']

    print "{0:15} had {1} SYNs and {2} SYN-ACKs".format(s, syns, synacks)
