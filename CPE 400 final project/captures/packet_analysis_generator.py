from scapy.all import rdpcap

def find_top5_ips(pcap_file, target_ip):
    packets = rdpcap(pcap_file)

    # Dictionaries to store counts of source and destination IPs
    src_ip_counts = {}
    dest_ip_counts = {}

    # Count occurrences of source and destination IPs
    for packet in packets:
        if 'IP' in packet:
            src_ip = packet['IP'].src
            dest_ip = packet['IP'].dst

            # Count source IPs when target IP is the destination
            if dest_ip == target_ip:
                src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1

            # Count destination IPs when target IP is the source
            if src_ip == target_ip:
                dest_ip_counts[dest_ip] = dest_ip_counts.get(dest_ip, 0) + 1

    # Find the top 5 source IPs
    top5_src_ips = sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # Find the top 5 destination IPs
    top5_dest_ips = sorted(dest_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # Display the top 5 source IPs
    print(f"\nTop 5 Source IPs when {target_ip} is the destination:")
    for ip, count in top5_src_ips:
        print(f"Source IP Address: {ip}, Occurrences: {count}")

    # Display the top 5 destination IPs
    print(f"\nTop 5 Destination IPs when {target_ip} is the source:")
    for ip, count in top5_dest_ips:
        print(f"Destination IP Address: {ip}, Occurrences: {count}")



#start Script: 


#*print("\nDay 1:")
#find_top5_ips('day1.pcapng', '192.168.1.223')
#print("\nDay 2:")
#find_top5_ips('day2a.pcapng', '192.168.1.223')
#print("\nDay 3:")
#find_top5_ips('day3a.pcapng', '192.168.1.223')

#print("\nMorning 1:")
#find_top5_ips('morning1.pcapng', '192.168.1.223')
#print("\nMorning 2:")
#find_top5_ips('morning2.pcapng', '192.168.1.223')
#print("\nMorning 3:")
#find_top5_ips('morning3.pcapng', '192.168.1.223')

#print("\nNight 1:")
#find_top5_ips('night1.pcapng', '192.168.1.223')
#print("\nNight 2:")
#find_top5_ips('night2.pcapng', '192.168.1.223')
#print("\nNight 3:")
#find_top5_ips('night3.pcapng', '192.168.1.223')