import dpkt, socket, sys

SYN_SYNACK_RATIO = 3

#=FUNCTIONS===================================================================#


def tcpFlags(tcp):
    """Returns a list of the set flags in this TCP packet."""
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
    """
    Return negative if ip1 < ip2, 0 if they are equal, positive if ip1 > ip2.
    """
    return sum(map(int, ip1.split('.'))) - sum(map(int, ip2.split('.')))

# get local ip address
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
localIP = s.getsockname()[0]
s.close()

f = open('example.pcap')
pcap = dpkt.pcap.Reader(f)
print(pcap)

suspects = dict() # Dictionary of suspects. suspect's IP: {# SYNs, # SYN-ACKs}
curPacket = 0     # Current packet number.

# Analyze captured packets.
for ts, buf in pcap:
    curPacket += 1

    # Ignore malformed packets
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.UnpackError, IndexError):
        continue

    # Packet must include IP protocol to get TCP
    ip = eth.data
    if not ip:
        continue

    # Skip packets that are not TCP
    tcp = ip.data
    if type(tcp) != dpkt.tcp.TCP:
        continue

    # Get all of the set flags in this TCP packet
    tcpFlag = tcpFlags(tcp)

    srcIP = socket.inet_ntoa(ip.src)
    dstIP = socket.inet_ntoa(ip.dst)

    # Fingerprint possible suspects.
    if {'SYN'} == set(tcpFlag):          # A 'SYN' request.
        if srcIP not in suspects: suspects[srcIP] = {'SYN': 0, 'SYN-ACK': 0}
        suspects[srcIP]['SYN'] += 1
    elif {'SYN', 'ACK'} == set(tcpFlag): # A 'SYN-ACK' reply.
        if dstIP not in suspects: suspects[dstIP] = {'SYN': 0, 'SYN-ACK': 0}
        suspects[dstIP]['SYN-ACK'] += 1

# Prune unlikely suspects based on ratio of SYNs to SYN-ACKs.
for s in suspects.keys():
    if suspects[s]['SYN'] < (suspects[s]['SYN-ACK'] * SYN_SYNACK_RATIO):
        del suspects[s]

# Output results.
print "Analyzed", curPacket, "packets:"

if not suspects:
    print 'no suspicious packets detected...'

for s in sorted(suspects.keys(), cmp=compare_IPs):
    syns = suspects[s]['SYN']
    synacks = suspects[s]['SYN-ACK']

    print "{0:15} had {1} SYNs and {2} SYN-ACKs".format(s, syns, synacks)

# srcIP=[]

# for pkt in packets:
#     if IP in pkt:
#         srcIP.append(pkt[IP].src + " > " + pkt[IP].dst)

# cnt = Counter()
# for ip in srcIP:
#     cnt[ip] += 1

# table = PrettyTable(["IP", "Count"])
# for ip, count in cnt.most_common():
#     table.add_row([ip, count])
# print(table)
