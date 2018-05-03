from scapy.all import *
paquetes = rdpcap('sniff_ethernet.cap')
freq = {
        'broadcast': {},
        'unicast': {}
        }
for pkt in paquetes:
    if pkt.getlayer(1) != None:
        
        # Ethernet
        tipo = 'broadcast' if pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' else 'unicast'
        proto = pkt.getlayer(1).name
        
        print(tipo)
        print(proto)
        # Wifi
        #
        if proto in freq[tipo]:
            freq[tipo][proto] = freq[tipo][proto] + 1
        else:
            freq[tipo][proto] = 0

print(freq)
