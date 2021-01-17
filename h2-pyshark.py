"""
Follow a TCP stream with pyshark.
"""
import sys
import pyshark
from h2.config import H2Configuration
from h2.connection import H2Connection

# Change FILENAME to your pcap file's name.
FILENAME = "./pcap-sample/http2-h2c.pcap"
# Change STREAM_NUMBER to the stream number you want to follow.
STREAM_NUMBER = 0

# open the pcap file, filtered for a single TCP stream
cap = pyshark.FileCapture(FILENAME)

# sys.exit()

config = H2Configuration(client_side=False)
conn = H2Connection(config=config)

curr_pkt = cap.next()
while curr_pkt:
    # print(dir(packet.tcp), type(packet.tcp), packet)
    try:
        if "HTTP2" in str(curr_pkt.layers):
            tmp_data = curr_pkt.tcp.payload.encode()
            h_list = [e for e in tmp_data.decode("utf-8").split(":")]
            tdata = "".join(h_list)
            byte_data = (
                bytes.fromhex(tdata)
                .decode("utf-8")
                .replace("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n", "")
            )
            print(byte_data)
            conn.receive_data(byte_data)
        curr_pkt = cap.next()
    except StopIteration:
        break
