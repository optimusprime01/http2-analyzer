"""
Follow a TCP stream with pyshark.
"""
import sys
import pyshark
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.frame_buffer import FrameBuffer
from h2.frame_buffer import HeadersFrame
from hyperframe.frame import *
from hpack import Decoder

decoder = Decoder()

# Change INPUT_CONFIG to your pcap file's name and server/client's IP address
INPUT_CONFIG = {
    "pcap": "./pcap-sample/http2-h2c.pcap",
    "client": "10.9.0.2",
    "server": "139.162.123.134",
}
# Change STREAM_NUMBER to the stream number you want to follow.
STREAM_NUMBER = 0
# Switching protocol check
SWITCHING_PRTOCOL_TXT = "HTTP/1.1 101 Switching Protocols"

# open the pcap file, filtered for a single TCP stream
cap = pyshark.FileCapture(INPUT_CONFIG["pcap"])

sess_index = set()
curr_pkt = cap.next()
while curr_pkt:
    try:
        sess_index.add(curr_pkt.tcp.stream)
        curr_pkt = cap.next()
    except StopIteration:
        break
    except:
        pass
print(sess_index)
cap.reset()

# server_config = H2Configuration(client_side=False)
# client_config = H2Configuration(client_side=True)
# server = H2Connection(config=server_config)
# client = H2Connection(config=client_config)
server_buffer = FrameBuffer(server=True)
server_buffer.max_frame_size = 262144
client_buffer = FrameBuffer(server=False)
client_buffer.max_frame_size = 262144

client_events = []
server_events = []


curr_pkt = cap.next()
while curr_pkt:
    # print(dir(packet.tcp), type(packet.tcp), packet)
    try:
        if "HTTP2" in str(curr_pkt.layers):
            tmp_data = curr_pkt.tcp.payload.encode()
            h_list = [e for e in tmp_data.decode("utf-8").split(":")]
            tdata = "".join(h_list)
            byte_data = bytes.fromhex(tdata)
            try:
                byte_data_str = byte_data.decode("utf-8")
            except:
                byte_data_str = ""
            if SWITCHING_PRTOCOL_TXT in byte_data_str and curr_pkt.ip.dst == INPUT_CONFIG["client"]:
                # client.initiate_upgrade_connection()
                # print(client.data_to_send())
                curr_pkt = cap.next()
                continue
            # print([curr_pkt.ip.dst, byte_data], type(byte_data))
            if curr_pkt.ip.dst == INPUT_CONFIG["client"]:
                # events = client.receive_data(byte_data)
                # print(events)
                client_buffer.add_data(byte_data)
                # print(client_buffer.data)
                for event in client_buffer:
                    # print("Client event: {0}".format(event))
                    client_events.append(event)
            elif curr_pkt.ip.dst == INPUT_CONFIG["server"]:
                # print("here")
                # events = server.receive_data(byte_data)
                # print(events)
                server_buffer.add_data(byte_data)
                for event in server_buffer:
                    # print("Server event: {0}".format(event))
                    server_events.append(event)
        curr_pkt = cap.next()
    except StopIteration:
        break

for event in client_events:
    print("Client event: {0}, streamid: {1}".format(event, event.stream_id))
    if isinstance(event, HeadersFrame):
        print("Client headers: {0}".format(decoder.decode(event.data)))
    if isinstance(event, DataFrame):
        print("Client received data: {0}".format(event.data.decode("utf-8")))

for event in client_events:
    print("Server event: {0}, streamid: {1}".format(event, event.stream_id))
    if isinstance(event, HeadersFrame):
        print("Server headers: {0}".format(decoder.decode(event.data)))
    if isinstance(event, DataFrame):
        print("Server received data: {0}".format(event.data.decode("utf-8")))
