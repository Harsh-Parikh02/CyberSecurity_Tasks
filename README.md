# PacketPulse

PacketPulse is a powerful network sniffer tool that captures and analyzes network packets in real-time. This application uses a GUI built with Tkinter to display captured packets, including Ethernet, IPv4, and TCP packet details.

## Features

- **Real-Time Packet Capturing**: Capture packets in real-time from the network interface.
- **Detailed Packet Analysis**: Analyze Ethernet, IPv4, and TCP packets and display their details.
- **GUI Interface**: User-friendly interface built with Tkinter to display captured packets.
- **Domain Name Resolution**: Resolve and display domain names for IP addresses.

## Prerequisites

- Python 3.x
- `socket` library (standard with Python)
- `struct` library (standard with Python)
- `tkinter` library (standard with Python)

## Getting Started

### Installation

1. Run the PacketPulse application:
    ```sh
    python packet_pulse.py
    ```

## Usage

1. **Run the Application**: Start the application by running `packet_pulse.py`.
2. **Packet Capturing**: The application automatically starts capturing packets and displays them in the GUI.
3. **Packet Analysis**: View detailed information about Ethernet, IPv4, and TCP packets, including source and destination addresses, protocol, and more.

## Functionalities

### 1. GUI Setup
- The GUI is created using Tkinter. It includes a `ScrolledText` widget to display captured packets.
- The `NetworkSniffer` class initializes the GUI and starts the packet sniffer.

### 2. Packet Sniffer
- **Raw Socket Creation**: A raw socket is created and bound to the public network interface to capture packets.
    ```python
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    ```

### 3. Packet Analysis
- **Ethernet Frame**: The `ethernet_frame` method extracts destination MAC, source MAC, and protocol information from the packet.
    ```python
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    ```

- **IPv4 Packet**: If the Ethernet protocol indicates IPv4, the `ipv4_packet` method extracts version, header length, TTL, protocol, and IP addresses.
    ```python
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ```

- **TCP Segment**: If the protocol indicates TCP, the `tcp_segment` method extracts source and destination ports, sequence and acknowledgment numbers, flags, and data offset.
    ```python
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    ```

### 4. Domain Name Resolution
- **Domain Resolution**: The `get_domain_name` method resolves domain names for the IP addresses.
    ```python
    domain = socket.gethostbyaddr(ip)[0]
    ```

### 5. GUI Update
- **Text Area Update**: The `update_text_area` method updates the GUI with the captured packet details.
    ```python
    self.text_area.insert(tk.END, text + '\n')
    self.text_area.see(tk.END)
    self.root.update_idletasks()
    ```

## Contributing

We welcome contributions to PacketPulse! If you have any ideas or improvements, please feel free to submit a pull request or open an issue.

## Contact

For any inquiries or support, please contact parikhharsh8545@gmail.com.

---

Happy Sniffing with PacketPulse! 😊
