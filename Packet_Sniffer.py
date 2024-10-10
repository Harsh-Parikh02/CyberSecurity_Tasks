import socket
import struct
import tkinter as tk
from tkinter import scrolledtext

class NetworkSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        self.root.geometry("800x600")
        
        # Create a ScrolledText widget to display captured packets
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=100, height=30)
        self.text_area.pack(padx=10, pady=10)
        
        # Start capturing packets
        self.start_sniffer()
        
    def start_sniffer(self):
        # Create a raw socket and bind it to the public interface
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        while True:
            raw_data, addr = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
            packet_info = f'\nEthernet Frame:\nDestination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}'
            
            if eth_proto == 8:  # If the protocol is IPv4
                version, header_length, ttl, proto, src_ip, target_ip, src_domain, target_domain, data = self.ipv4_packet(data)
                packet_info += f'\nIPv4 Packet:\nVersion: {version}, Header Length: {header_length}, TTL: {ttl}'
                packet_info += f'\nProtocol: {proto}, Source IP: {src_ip} (Domain: {src_domain}), Target IP: {target_ip} (Domain: {target_domain})'
                
                if proto == 6:  # If the protocol is TCP
                    src_port, dest_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = self.tcp_segment(data)
                    packet_info += f'\nTCP Segment:\nSource Port: {src_port}, Destination Port: {dest_port}'
                    packet_info += f'\nSequence: {sequence}, Acknowledgment: {acknowledgment}'
                    packet_info += f'\nFlags: URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}'

            # Update the GUI with the captured packet details
            self.update_text_area(packet_info)

    def update_text_area(self, text):
        self.text_area.insert(tk.END, text + '\n')
        self.text_area.see(tk.END)
        self.root.update_idletasks()

    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        src_ip = self.ipv4(src)
        target_ip = self.ipv4(target)
        
        # Resolve domain names for the IP addresses
        src_domain = self.get_domain_name(src_ip)
        target_domain = self.get_domain_name(target_ip)
        
        return version, header_length, ttl, proto, src_ip, target_ip, src_domain, target_domain, data[header_length:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    def tcp_segment(self, data):
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return src_port, dest_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    def get_domain_name(self, ip):
        try:
            domain = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            domain = "Unknown"
        return domain

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSniffer(root)
    root.mainloop()
