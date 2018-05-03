from scapy.all import *
cantidad = 100000
placa = "wlp2s0"

def monitor_callback(pkt):
    print(pkt.show())

paquetes = sniff(iface=placa, prn=monitor_callback, filter="not host 192.168.0.181" , count=cantidad)
wrpcap("sniff.cap", paquetes)
