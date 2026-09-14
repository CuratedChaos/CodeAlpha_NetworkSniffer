from scapy.all import (
    sniff,
    get_if_list,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    Raw
)
from datetime import datetime


packet_count = 0

protocol_stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0
}


def get_protocol(packet):
    """Identify the main protocol used by the packet."""

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(IP) or packet.haslayer(IPv6):
        return "IP"

    return "Other"


def get_addresses(packet):
    """Return source and destination IP addresses."""

    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst

    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst

    return "N/A", "N/A"


def get_ports(packet):
    """Return source and destination ports for TCP/UDP packets."""

    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport

    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport

    return None, None


def get_payload(packet):
    """Extract readable payload data when available."""

    if not packet.haslayer(Raw):
        return "None"

    payload = bytes(packet[Raw].load)

    try:
        text = payload.decode("utf-8", errors="replace")
        text = text.replace("\n", " ")
        text = text.replace("\r", " ")
        text = text.strip()

        if not text:
            return "None"

        printable = sum(
            char.isprintable() or char.isspace()
            for char in text
        )

        ratio = printable / len(text)

        if ratio >= 0.85:
            if len(text) > 100:
                return text[:100] + "..."

            return text

    except Exception:
        pass

    return "[Encrypted/Binary Data]"


def packet_callback(packet):
    """Process and display information about each captured packet."""

    global packet_count

    packet_count += 1

    protocol = get_protocol(packet)
    protocol_stats[protocol] += 1

    source, destination = get_addresses(packet)
    source_port, destination_port = get_ports(packet)

    print("\n" + "=" * 60)
    print(f"PACKET #{packet_count}")
    print("=" * 60)

    print(
        f"Time        : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(f"Protocol    : {protocol}")
    print(f"Source      : {source}")
    print(f"Destination : {destination}")

    if source_port is not None:
        print(f"Source Port : {source_port}")
        print(f"Dest Port   : {destination_port}")

    if packet.haslayer(TCP):
        print(f"TCP Flags   : {packet[TCP].flags}")

    print(f"Packet Size : {len(packet)} bytes")
    print(f"Payload     : {get_payload(packet)}")


def print_statistics():
    """Display packet capture statistics."""

    print("\n\n" + "=" * 60)
    print("             PACKET STATISTICS")
    print("=" * 60)

    print(f"Total Packets : {packet_count}")
    print(f"TCP           : {protocol_stats['TCP']}")
    print(f"UDP           : {protocol_stats['UDP']}")
    print(f"ICMP          : {protocol_stats['ICMP']}")
    print(f"Other         : {protocol_stats['Other']}")

    print("=" * 60)


def get_interface():
    """Display available interfaces and let the user select one."""

    interfaces = get_if_list()

    print("\nAvailable Network Interfaces")
    print("-" * 60)

    for index, interface in enumerate(interfaces, start=1):
        print(f"{index}. {interface}")

    while True:
        try:
            choice = int(input("\nSelect interface: "))

            if 1 <= choice <= len(interfaces):
                selected = interfaces[choice - 1]

                print(f"\nSelected interface: {selected}")

                return selected

            print("Invalid selection.")

        except ValueError:
            print("Please enter a valid number.")


def get_capture_count():
    """Allow the user to choose the number of packets to capture."""

    print("\nCapture Options")
    print("-" * 30)
    print("1. Capture 20 packets")
    print("2. Capture 50 packets")
    print("3. Capture 100 packets")
    print("4. Capture continuously")

    while True:
        choice = input("\nEnter your choice (1-4): ").strip()

        if choice == "1":
            return 20

        if choice == "2":
            return 50

        if choice == "3":
            return 100

        if choice == "4":
            return 0

        print("Invalid choice. Please enter 1, 2, 3, or 4.")


def main():
    """Main program function."""

    print("=" * 60)
    print("             CODEALPHA NETWORK SNIFFER")
    print("=" * 60)

    interface = get_interface()
    packet_limit = get_capture_count()

    print("\nStarting packet capture...")
    print(f"Interface   : {interface}")

    if packet_limit == 0:
        print("Mode        : Continuous")
    else:
        print(f"Packet Limit: {packet_limit}")

    print("Press CTRL+C to stop.")
    print("=" * 60)

    try:
        if packet_limit == 0:
            sniff(
                iface=interface,
                prn=packet_callback,
                store=False
            )
        else:
            sniff(
                iface=interface,
                count=packet_limit,
                prn=packet_callback,
                store=False
            )

    except KeyboardInterrupt:
        print("\n\nPacket capture stopped by user.")

    except PermissionError:
        print("\nPermission denied.")
        print("Please run PowerShell as Administrator.")

    except Exception as error:
        print(f"\nCapture error: {error}")

    finally:
        print_statistics()


if __name__ == "__main__":
    main()