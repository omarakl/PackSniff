import os
from scapy.all import *


def sniffer(packet):
	if packet.haslayer(TCP):
		print("\n")
		print("TCP packet !")
		print("\n")
		src_ip = packet[IP].src		# extracts the IP of the packet sender
		dst_ip = packet[IP].dst		# extracts the IP of the packet reciever
		src_mac = packet.src		# extracts the MAC address of the sender
		dst_mac = packet.dst		# extracts thr MAC address of the reciever
		src_port = packet.sport		# extracts the port of the packet sender
		dst_port = packet.dport		# extracts the port of the packet reciever

		if packet.haslayer(Raw):		# checks if the packet contains data
			print(packet[Raw].load)	# prints the packet's data
		print("\n")
		print("Packet Information : ")
		print("\n")
		print("Source IP 			: " + src_ip)
		print("Destination IP 			: " + dst_ip)
		print("Source MAC 			: " + src_mac)
		print("Destination MAC 		: " + dst_mac) 
		print("Source Port 			: " + str(src_port))
		print("Destination Port			: " + str(dst_port))
		print("Packet Size 			:" + str(len(packet[TCP])) + " byte")
		print("\n")
		print("###############################")
		print("\n")

	elif packet.haslayer(UDP):
		print("\n")
		print("UDP packet !")
		print("\n")
		src_ip = packet[IP].src		# extracts the IP of the packet sender
		dst_ip = packet[IP].dst		# extracts the IP of the packet reciever
		src_mac = packet.src		# extracts the MAC address of the sender
		dst_mac = packet.dst		# extracts thr MAC address of the reciever
		src_port = packet.sport		# extracts the port of the packet sender
		dst_port = packet.dport		# extracts the port of the packet reciever

		if packet.haslayer(Raw):		# checks if the packet contains data
			print(packet[Raw].load)	# prints the packet's data
		print("\n")
		print("Packet Information : ")
		print("\n")
		print("Source IP 			: " + src_ip)
		print("Destination IP 			: " + dst_ip)
		print("Source MAC 			: " + src_mac)
		print("Destination MAC 		: " + dst_mac) 
		print("Source Port 			: " + str(src_port))
		print("Destination Port 		: " + str(dst_port))
		print("Packet Size 			:" + " " + str(len(packet[UDP])) + " byte")
		print("\n")
		print("###############################")
		print("\n")

	elif packet.haslayer(ICMP):
		print("\n")
		print("ICMP packet !")
		print("\n")
		src_ip = packet[IP].src		# extracts the IP of the packet sender
		dst_ip = packet[IP].dst		# extracts the IP of the packet reciever
		src_mac = packet.src		# extracts the MAC address of the sender
		dst_mac = packet.dst		# extracts thr MAC address of the reciever

		if packet.haslayer(Raw):		# checks if the packet contains data
			print(packet[Raw].load)	# prints the packet's data
		print("\n")
		print("Packet Information : ")
		print("\n")
		print("Source IP 			: " + src_ip)
		print("Destination IP 			: " + dst_ip)
		print("Source MAC 			: " + src_mac)
		print("Destination MAC 		: " + dst_mac) 
		print("Packet Size 			:" + " " + str(len(packet[ICMP])) + " byte")
		print("\n")
		print("###############################")
		print("\n")

		
print("\n")
print("####### 		PackSniff started and waiting for packets !		#######")
sniff(prn=sniffer)