from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import math

def calcular(paquetes):
    freq = {}
    for pkt in paquetes:
        tipo = 'who-has' if pkt.op == 1 else 'is-at'
        if tipo == 'who-has':
            ip = pkt.pdst
        else:
            ip = pkt.psrc
        
        if tipo == 'who-has':
            freq[ip] = freq[ip] + 1 if ip in freq else 0
    ipDistinguida=ip
    for k in freq:
            if freq[k] > freq[ipDistinguida]:
                ipDistinguida=k
    


    return (ipDistinguida,freq)

if __name__ == "__main__":
    print('Analizo primer sniff: Ethernet Casa')
    paquetes = rdpcap('../datos/sniff_casa_fede.cap')
    (ipDistinguida, freq) = calcular(paquetes[ARP])
    print("Ip distinguida: "+ ipDistinguida + ". Cantidad de apariciones:"+str(freq[ipDistinguida]))
    print(freq);
    print('Analizo segundo sniff: Wifi Laboratorios DC')
    paquetes = rdpcap('../datos/sniff_wifi_labo_filtrado.cap')
    (ipDistinguida, freq) = calcular(paquetes[ARP])
    print("Ip distinguida: "+ ipDistinguida + ". Cantidad de apariciones:"+str(freq[ipDistinguida]))
    print(freq);
    print('Analizo tercer sniff:Ethernet Casa 2')
    paquetes = rdpcap('../datos/sniff_ethernet.cap')
    (ipDistinguida, freq) = calcular(paquetes[ARP])
    print("Ip distinguida: "+ ipDistinguida + ". Cantidad de apariciones:"+str(freq[ipDistinguida]))
    print(freq);
    
