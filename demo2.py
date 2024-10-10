import os
import fcntl
import struct
import socket
import binascii

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tuntap(ifname='tun1', src_ip='10.20.0.104'):
    """Create and configure a TUN interface."""
    tun_fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', ifname.encode(), IFF_TUN | IFF_NO_PI)
    try:
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    except IOError as e:
        os.close(tun_fd)
        raise RuntimeError(f"Failed to create TUN interface {ifname}: {e}") 

    ### Configuring  the interface ###
    os.system(f"ip addr add {src_ip}/24 dev {ifname}")
    os.system(f"ip link set {ifname} up")
    return tun_fd

def create_raw_socket(interface='tun0'):
    """Create and bind a raw socket to the specified interface."""
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        if interface not in os.listdir('/sys/class/net/'):
            raise RuntimeError(f"Interface {interface} does not exist. Please create and bring up the interface first.")
        raw_socket.bind((interface, 0))
        print(f"Raw socket created and bound to interface {interface}.")
    except OSError as e:
        raise RuntimeError(f"Failed to create or bind raw socket: {e}")
    return raw_socket

def format_packet_hex(packet):
    """Format packet data into a hexadecimal string for better visibility."""
    return binascii.hexlify(packet).decode('utf-8')

def receive_from_raw_socket(raw_sock, tun_fd):
    """Receive packets from the raw socket, write them to tun1, and print them."""
    while True:
        try:
            packet, addr = raw_sock.recvfrom(2048)  ### Receiving from the raw socket ###
            print(f"Received packet from raw socket: {addr}")
            print(f"Hexadecimal Format:\n{format_packet_hex(packet)}")
            ### Writing the packet to tun1 ###
            os.write(tun_fd, packet)
        except KeyboardInterrupt:
            print("Stopping packet handling.")
            break

def setup_iptables(src_ip):
    """Setup iptables rules to allow traffic to the TUN interface."""
    os.system(f"iptables -A INPUT -i tun1 -j ACCEPT")
    os.system(f"iptables -A OUTPUT -o tun1 -j ACCEPT")
    os.system(f"iptables -A FORWARD -i tun1 -j ACCEPT")
    os.system(f"iptables -A FORWARD -o tun1 -j ACCEPT")

def main():
    print("Creating TUN interface tun1...")
    tun_fd = create_tuntap('tun1', '10.20.0.104')
    print("TUN interface tun1 created and configured.")
    
    setup_iptables('10.20.0.104')
    
    raw_sock = create_raw_socket(interface='tun0')  
    
    print("Waiting for packets on tun1...")
    receive_from_raw_socket(raw_sock, tun_fd)

if __name__ == '__main__':
    main()
