from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import math
lengthWhoHasPackets=0


def imprimirTabla(freq):
#La tabla debe contener
#<ip,informacion del simbolo, probabilidad del simbolo>
#Entropia  y entropia maxima
    global lengthWhoHasPackets
    #print(" Indice  | IP               | Probabilidad    | Informacion     ")
    print(" "+"{:<7}".format("Indice")+" | "+"{:<15}".format("IP")+" | "+"{:<18}".format("Probabilidad")+" | "+"{:<18}".format("Informacion"))
    entropia = 0
    indice =0
    ipDistinguida=list(freq.keys())[0]
    for _ip in freq:
            p = (float)( freq[_ip]) / (float) (lengthWhoHasPackets)
            i = (float) (-1) * (float)(math.log(p,2))
            entropia += p * i
            indice = indice +1
            if freq[_ip] > freq[ipDistinguida]:
                ipDistinguida=_ip
            print(" "+"{:<7}".format(str(indice))+" | "+"{:<15}".format(str(_ip))+" | "+"{:<18}".format(str(p))+" | "+"{:<18}".format(str(i)))
    max_entropia = math.log(len(freq),2)
    print("H(S2)="+str(entropia))
    print("Max_H(S2)="+str(max_entropia))
    print("Ip distinguida: "+ ipDistinguida +" | Cantidad de apariciones: "+str(freq[ipDistinguida]))
    

def obtenerFrecuencias(paquetes):
    global lengthWhoHasPackets
    freq = {}
    
    for pkt in paquetes:
        tipo = 'who-has' if pkt.op == 1 else 'is-at'
        if tipo == 'who-has':
            ip = pkt.pdst
            lengthWhoHasPackets=lengthWhoHasPackets+1
        else:
            ip = pkt.psrc
        
        if tipo == 'who-has':
            freq[ip] = freq[ip] + 1 if ip in freq else 1



    
    return (freq)



if __name__ == "__main__":
    print('Analizo primer sniff: Ethernet Casa')
    paquetes = rdpcap('../datos/sniff_casa_fede.cap')
    freq = obtenerFrecuencias(paquetes[ARP])
    imprimirTabla(freq)
    print('Analizo segundo sniff: Wifi Laboratorios DC')
    paquetes = rdpcap('../datos/sniff_wifi_labo_filtrado.cap')
    freq = obtenerFrecuencias(paquetes[ARP])
    imprimirTabla(freq)
    print('Analizo tercer sniff:Ethernet Casa 2')
    paquetes = rdpcap('../datos/sniff_ethernet.cap')
    freq = obtenerFrecuencias(paquetes[ARP])
    imprimirTabla(freq)
    
