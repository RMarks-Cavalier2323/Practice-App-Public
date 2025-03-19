import pyshark
import pandas as pd
from sklearn.preprocessing import LabelEncoder

def extract_features(pcap_file):
    cap = pyshark.FileCapture(pcap_file)

    data = []
    
    for packet in cap:
        try:
            length = len(packet)
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer
            timestamp = packet.sniff_time  # Capture timestamp
            tcp_flag = packet.tcp.flags if hasattr(packet, 'tcp') else None  # Capture TCP flags if available
            flow_id = f"{src_ip}_{dst_ip}_{protocol}"  # Generate a simple Flow ID

            # Append all values as a row
            data.append([length, timestamp, tcp_flag, flow_id, src_ip, dst_ip, protocol])

        except AttributeError:
            continue

    # Convert to DataFrame
    df = pd.DataFrame(data, columns=["Packet_Length", "Timestamp", "TCP_Flags", "Flow_ID", "Source_IP", "Destination_IP", "Protocol"])

    # Encode categorical data (IP addresses, protocol)
    label_encoder = LabelEncoder()
    df["Source_IP_Encoded"] = label_encoder.fit_transform(df["Source_IP"])
    df["Destination_IP_Encoded"] = label_encoder.fit_transform(df["Destination_IP"])
    df["Protocol_Encoded"] = label_encoder.fit_transform(df["Protocol"])

    # Save to CSV
    df.to_csv("extracted_data.csv", index=False)

    return df

# Example usage
if __name__ == "__main__":
    pcap_file = '/home/ryanPi/network_capture.pcap'
    df = extract_features(pcap_file)
    print("Extracted data saved to extracted_data.csv")

