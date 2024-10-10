import os
import fcntl
import struct
import socket
import time

# Constants for TUN interface
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tuntap(ifname='tun0', src_ip='10.20.0.103'):
    """Create and configure a TUN interface."""
    tun_fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', ifname.encode(), IFF_TUN | IFF_NO_PI)
    try:
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    except IOError as e:
        os.close(tun_fd)
        raise RuntimeError(f"Failed to create TUN interface {ifname}: {e}")

    # Configure the interface
    os.system(f"ip addr add {src_ip}/24 dev {ifname}")
    os.system(f"ip link set {ifname} up")
    return tun_fd

def send_udp_packets(tun_fd, dst_ip='10.20.0.106', dst_port=5683):
    """Send UDP packets with IP and UDP headers, similar to the UDP_client."""
    for i in range(50):
        # Create a payload message (same as UDP_client)
        payload = f"Packet {i + 1}".encode()
        print(f"Sending UDP packet {i + 1} with payload: {payload}")
        
        # Create IP header (similar to UDP_client)
        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            69,  # Version and IHL
            0,   # DSCP and ECN
            20 + 8 + len(payload),  # Total length (IP header + UDP header + payload)
            54321,  # Identification
            0,  # Flags and Fragment Offset
            255,  # TTL
            socket.IPPROTO_UDP,  # Protocol
            0,  # Header checksum
            socket.inet_aton('10.20.0.103'),  # Source IP
            socket.inet_aton(dst_ip)  # Destination IP
        )
        
        # Create UDP header (similar to UDP_client)
        udp_header = struct.pack(
            '!HHHH',
            12345,  # Source port
            dst_port,  # Destination port
            8 + len(payload),  # UDP length (header + data)
            0  # UDP checksum
        )

        # Combine headers and payload into a complete packet
        packet = ip_header + udp_header + payload
        
        # Write packet to TUN interface
        os.write(tun_fd, packet)
        time.sleep(2)  # Wait 2 seconds before sending the next packet

def main():
    print("Creating TUN interface tun0...")
    tun_fd = create_tuntap('tun0', '10.20.0.103')
    print("TUN interface tun0 created and configured.")
    
    print("Ready to send UDP packets.")
    send_udp_packets(tun_fd, dst_ip='10.20.0.106', dst_port=5683)

if __name__ == '__main__':
    main()
