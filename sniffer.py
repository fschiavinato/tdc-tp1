from scapy.all import *
cantidad = 100000
placa = "enp3s0"

def monitor_callback(pkt):
    print(pkt.show())

paquetes = sniff(iface=placa, prn=monitor_callback , count=cantidad)
wrpcap("sniff.cap", paquetes)
