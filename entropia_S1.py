from scapy.all import *
import math

paquetes = rdpcap('sniff_ethernet.cap')
freq = {}
paquetes = paquetes.filter(lambda pkt: pkt.getlayer(1) != None and Ether in pkt)
for pkt in paquetes:
    # Ethernet
    tipo = 'broadcast' if pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' else 'unicast'
    proto = pkt.getlayer(1).name
    
    # Wifi
    #

    freq[(tipo,proto)] = freq[(tipo,proto)] + 1 if (tipo,proto) in freq else 0

entropia = 0
for k in freq:
        p = freq[k] / len(paquetes) 
        entropia += -p * math.log(p)

max_entropia = math.log(len(freq))
print(freq)
print(entropia)
print(max_entropia)
























