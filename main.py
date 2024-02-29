from scapy.all import *


# USEFUL SCAPY TCP FlAG DOC IN THE FUTURE: https://stackoverflow.com/questions/20429674/get-tcp-flags-with-scapy

def check_port(hostname, port):
    """
     Checks if a specific port on a given hostname is open by sending a SYN packet.

     :param hostname: The hostname or IP address of the target.
     :type hostname: str
     :param port: The port number to check.
     :type port: int

     :return: None
     :rtype: None
     """
    # Craft a SYN packet
    syn_packet = IP(dst=hostname) / TCP(dport=port, flags='S')

    # Send the packet and wait for a response
    response = sr1(syn_packet, timeout=0.5, verbose=False)

    # Check if a response was received
    if response and response.haslayer(TCP):
        # Check if the TCP flags indicate an open port
        if response[TCP].flags.S and response[TCP].flags.A:  # SYN-ACK
            print(f"Port {port} is open")
        else:
            print(f".")
    else:
        print(f".")


def scan_ports(hostname):
    """
    Scans a range of ports for a given hostname to check for open ports.

    :param hostname: The hostname or IP address of the target.
    :type hostname: str

    :return: None
    :rtype: None
    """
    print(f"Scanning ports for {hostname}...")
    for port in range(20, 1025):  # Range of ports to scan
        check_port(hostname, port)


if __name__ == "__main__":
    target_host = input("Enter the target host address: ")
    scan_ports(target_host)
