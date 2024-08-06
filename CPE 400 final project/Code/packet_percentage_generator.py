from scapy.all import IP, rdpcap

def get_percentages(file_path):
    num_packets = 0
    tcp_packets = 0
    udp_packets = 0
    num_successful_acks = 0

    # Read packets from the PCAP file
    packets = rdpcap(file_path)

    # Process each packet in the packet data
    for packet in packets:
        num_packets += 1

        if IP in packet:

            # Check if it's a TCP packet
            if packet.haslayer('TCP'):
                tcp_packets += 1

                # Check for successful TCP packets 
                if packet['TCP'].flags & 0x10 == 0x10:
                    num_successful_acks += 1

            # Check if it's a UDP packet
            elif packet.haslayer('UDP'):
                udp_packets += 1

    # Calculate percentages 
    percentage_tcp = round((tcp_packets / num_packets) * 100, 3) if num_packets > 0 else 0
    percentage_udp = round((udp_packets / num_packets) * 100, 3) if num_packets > 0 else 0
    percentage_successful = round((num_successful_acks / tcp_packets) * 100, 3) if num_packets > 0 else 0

    # Print results
    print(f"\nPercentage of TCP packets: {percentage_tcp:.3f}%")
    print(f"Percentage of UDP packets: {percentage_udp:.3f}%")
    print(f"Percentage of successful Acknowledgments: {percentage_successful:.3f}%")

#print("\nmorning 1: ")
#get_percentages('morning1.pcapng')
#print("\nmorning 2: ")
#get_percentages('morning2.pcapng')
#print("\nmorning 3: ")
#get_percentages('morning3.pcapng')


#print("\nDay 1: ")
#get_percentages('day1.pcapng')
#print("\nDay 2: ")
#get_percentages('day2.pcapng')
#print("\nDay 3: ")
#get_percentages('day3a.pcapng')

#print("\nNight 1: ")
#get_percentages('night1.pcapng')
#print("\nNight 2: ")
#get_percentages('night2.pcapng')
#print("\nNight 3: ")
#get_percentages('night3.pcapng')

print("normal: ")
get_percentages('normal1.pcapng')
