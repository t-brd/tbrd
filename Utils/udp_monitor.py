from scapy.all import sniff, UDP, IP
import argparse
import time

def decode_payload(payload):
    if len(payload) < 6:
        return "Payload too short"

    oui = payload[0:3].hex().upper()
    msg_type = payload[3]
    counter = int.from_bytes(payload[4:5], byteorder='big')
    body = payload[5:]

    return {
        "OUI": oui,
        "Type": f"0x{msg_type:02X}",
        "Counter": counter,
        "Payload Length": len(payload),
        "Body (hex)": body.hex()
    }

def udp_monitor():
    parser = argparse.ArgumentParser(description="Utility to monitor UDP traffic")
    parser.add_argument("interface", help="Interface to sniff")
    parser.add_argument("port", type=int, help="Port to sniff")
    args = parser.parse_args()    
    port = args.port
    interface = args.interface
   
    print(f"Sniffing UDP packets on port {port}... Press Ctrl+C to stop.\n")

    def handle_packet(pkt):
        if UDP in pkt and pkt[UDP].dport == port:
            timestamp = time.time()
            ip_layer = pkt[IP]
            payload = bytes(pkt[UDP].payload)
            decoded = decode_payload(payload)
            print(f"\n[{timestamp:.6f}] From {ip_layer.src}:{pkt[UDP].sport}")
            for k, v in decoded.items():
                print(f"  {k}: {v}")

    sniff(filter=f"udp port {port}", prn=handle_packet, store=0, iface=interface)

if __name__ == "__main__":
    udp_monitor()