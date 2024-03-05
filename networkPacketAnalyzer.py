import tkinter as tk
from tkinter import scrolledtext
from scapy.all import *

def packet_sniffer():
    def process_packet(packet):
        nonlocal output_text
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                payload = str(packet.payload)

                output_text.insert(tk.END, f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}\n")
                output_text.insert(tk.END, f"Payload Data: {payload}\n\n")
        except Exception as e:
            print(f"Error processing packet: {e}")

    # Create Tkinter window
    window = tk.Tk()
    window.title("Packet Sniffer")
    
    # Create a scrolled text widget for output
    output_text = scrolledtext.ScrolledText(window, width=80, height=20)
    output_text.pack()

    # Start packet capture using Scapy
    sniff(prn=process_packet, store=False)

    # Run Tkinter event loop
    window.mainloop()

# Start packet sniffer
packet_sniffer()
