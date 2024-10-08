from scapy.all import sniff

def print_welcome_message():
    print("*******************************************************")
    print("*          Network Packet Capture & Analysis          *")
    print("*                                                     *")
    print("* This program captures network packets based on      *")
    print("* user-defined BPF filters and manually parses the    *")
    print("* hex data of the captured packets.                   *")
    print("*                                                     *")
    print("* Protocols supported: ARP, IPv4, TCP, and UDP        *")
    print("*                                                     *")
    print("* How to use:                                         *")
    print("* 1. Choose a network interface to capture packets.   *")
    print("* 2. Enter a BPF filter (e.g., 'arp', 'tcp port 80'). *")
    print("* 3. Enter the number of packets to capture.          *")
    print("* 4. Enter 'clear' to exit the program.               *")
    print("*******************************************************\n")


def get_user_input():
    print("Select the BPF filter to capture specific types of traffic:")
    print("1. ARP only")
    print("2. IPv4 only")
    print("3. TCP (within IPv4)")
    print("4. UDP (within IPv4)")
    print("5. Default: ARP or (IPv4 with TCP/UDP)")

    option = input("Enter your option (1-5, default is 5): ") or "5"

    if option == "1":
        capture_filter = "arp"
    elif option == "2":
        capture_filter = "ip"
    elif option == "3":
        capture_filter = "ip and tcp"
    elif option == "4":
        capture_filter = "ip and udp"
    else:
        capture_filter = "arp or (ip and (tcp or udp))"

    interface = input(
        "Enter the network interface (default is 'wlp0s20f3', press Enter to use default): ") or "wlp0s20f3"

    # Error handling
    while True:
        try:
            packet_count = int(input("Enter the number of packets to capture (must be less than 5): "))
            if packet_count < 5:
                break
            else:
                print("Error: Packet count must be less than 5. Please try again.")
        except ValueError:
            print("Error: Invalid input. Please enter a valid integer.")

    return interface, capture_filter, packet_count



def parse_ethernet_header(hex_data):
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]

    dest_mac_readable = ':'.join(dest_mac[i:i + 2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i + 2] for i in range(0, 12, 2))

    print(f"Ethernet Header:")
    print(f"  Destination MAC: {dest_mac_readable}")
    print(f"  Source MAC: {source_mac_readable}")
    print(f"  EtherType: {ether_type}")

    return ether_type


def parse_arp_header(hex_data):
    hw_type = hex_data[0:4]
    proto_type = hex_data[4:8]
    hw_size = hex_data[8:10]
    proto_size = hex_data[10:12]
    opcode = hex_data[12:16]
    sender_mac = hex_data[16:28]
    sender_ip = hex_data[28:36]
    target_mac = hex_data[36:48]
    target_ip = hex_data[48:56]

    sender_mac_readable = ':'.join(sender_mac[i:i + 2] for i in range(0, 12, 2))
    target_mac_readable = ':'.join(target_mac[i:i + 2] for i in range(0, 12, 2))
    sender_ip_readable = '.'.join(str(int(sender_ip[i:i + 2], 16)) for i in range(0, 8, 2))
    target_ip_readable = '.'.join(str(int(target_ip[i:i + 2], 16)) for i in range(0, 8, 2))

    print(f"ARP Header:")
    print(f"  Hardware Type: {hw_type}")
    print(f"  Protocol Type: {proto_type}")
    print(f"  Hardware Size: {hw_size}")
    print(f"  Protocol Size: {proto_size}")
    print(f"  Opcode: {opcode}")
    print(f"  Sender MAC: {sender_mac_readable}")
    print(f"  Sender IP: {sender_ip_readable}")
    print(f"  Target MAC: {target_mac_readable}")
    print(f"  Target IP: {target_ip_readable}")


def parse_ipv4_header(hex_data):
    version_ihl = hex_data[0:2]
    version = int(version_ihl[0], 16)
    ihl = int(version_ihl[1], 16) * 4
    total_length = int(hex_data[4:8], 16)
    identification = hex_data[8:12]
    flags_fragment_offset = int(hex_data[12:16], 16)
    ttl = int(hex_data[16:18], 16)
    protocol = int(hex_data[18:20], 16)
    checksum = hex_data[20:24]
    source_ip = hex_data[24:32]
    dest_ip = hex_data[32:40]

    flags = (flags_fragment_offset >> 13) & 0b111
    fragment_offset = flags_fragment_offset & 0x1FFF

    source_ip_readable = '.'.join(str(int(source_ip[i:i + 2], 16)) for i in range(0, 8, 2))
    dest_ip_readable = '.'.join(str(int(dest_ip[i:i + 2], 16)) for i in range(0, 8, 2))

    print(f"IPv4 Header:")
    print(f"  Version: {version}")
    print(f"  IHL: {ihl} bytes")
    print(f"  Total Length: {total_length}")
    print(f"  Identification: {identification}")
    print(f"  Flags: {bin(flags)}")
    print(f"  Fragment Offset: {fragment_offset}")
    print(f"  TTL: {ttl}")
    print(f"  Protocol: {protocol}")
    print(f"  Header Checksum: {checksum}")
    print(f"  Source IP: {source_ip_readable}")
    print(f"  Destination IP: {dest_ip_readable}")

    return protocol, hex_data[ihl * 2:]


def parse_tcp_header(hex_data):
    source_port = int(hex_data[0:4], 16)
    dest_port = int(hex_data[4:8], 16)
    seq_num = hex_data[8:16]
    ack_num = hex_data[16:24]
    data_offset_flags = int(hex_data[24:28], 16)
    window_size = hex_data[28:32]
    checksum = hex_data[32:36]
    urg_pointer = hex_data[36:40]

    data_offset = (data_offset_flags >> 12) * 4
    flags = data_offset_flags & 0x1FF

    print(f"TCP Header:")
    print(f"  Source Port: {source_port}")
    print(f"  Destination Port: {dest_port}")
    print(f"  Sequence Number: {seq_num}")
    print(f"  Acknowledgment Number: {ack_num}")
    print(f"  Data Offset: {data_offset} bytes")
    print(f"  Flags: {bin(flags)}")
    print(f"  Window Size: {window_size}")
    print(f"  Checksum: {checksum}")
    print(f"  Urgent Pointer: {urg_pointer}")


def parse_udp_header(hex_data):
    source_port = int(hex_data[0:4], 16)
    dest_port = int(hex_data[4:8], 16)
    length = int(hex_data[8:12], 16)
    checksum = hex_data[12:16]

    print(f"UDP Header:")
    print(f"  Source Port: {source_port}")
    print(f"  Destination Port: {dest_port}")
    print(f"  Length: {length}")
    print(f"  Checksum: {checksum}")


def packet_callback(packet):
    raw_data = bytes(packet)
    hex_data = raw_data.hex()

    ether_type = parse_ethernet_header(hex_data)

    if ether_type == '0800':  # IPv4
        protocol, payload = parse_ipv4_header(hex_data[28:])
        if protocol == 6:  # TCP
            parse_tcp_header(payload)
        elif protocol == 17:  # UDP
            parse_udp_header(payload)
    elif ether_type == '0806':  # ARP
        parse_arp_header(hex_data[28:])


def capture_packets(interface, capture_filter, packet_count):
    print(f"\nStarting packet capture on {interface} with filter: {capture_filter}")
    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count)

if __name__ == "__main__":
    while True:
        print_welcome_message()
        interface, capture_filter, packet_count = get_user_input()
        capture_packets(interface, capture_filter, packet_count)

        user_choice = input("\nType 'clear' to exit or press Enter to return to main menu: ").strip().lower()
        if user_choice == "clear":
            print("Exiting the program.")
            break
