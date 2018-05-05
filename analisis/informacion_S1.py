from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import math

def calcular(paquetes):
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
    return (freq, entropia, max_entropia)


def tabla_informacion(freq, entropia, max_entropia):
    pd.series(freq)

def porcentaje_tipos(freq):
    pass

def porcentaje_proto(freq):
    pass

if __name__ == "__main__":
    paquetes = rdpcap('sniff_ethernet.cap')
    (freq, entropia, max_entropia) = calcular(paquetes)
    print(entropia)
    print(max_entropia)
    tabla_informacion(freq, entropia, max_entropia)
