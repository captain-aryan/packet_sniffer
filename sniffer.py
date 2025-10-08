from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
from colorama import init, Fore

# Text Colors
init()
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
yellow = Fore.YELLOW
reset = Fore.RESET

def sniff_packets(iface):
    if iface:
        sniff(prn = process_packet, iface = iface, store = False)
    else:
        sniff(prn = process_packet, store = False)

def process_packet(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        print(f"{blue}[+] {src_ip}:{src_port} --> {dst_ip}:{dst_port}{reset}")

    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        print(f"{green}[+] {src_ip} is making a HTTP request to {url} with method {method}{reset}")
        print(f"[+] HTTP Data:")
        print(f"{yellow}[+] {packet[HTTPRequest].show()}")

sniff_packets('eth0') # Set your interface
