"""
Follow a TCP stream with pyshark.
"""
import os
import sys
import json
import logging
from logging.config import dictConfig
import pyshark
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.frame_buffer import FrameBuffer
from h2.frame_buffer import HeadersFrame
from hyperframe.frame import *
from hpack import Decoder

log_conf = json.load(open("logging.json"))
dictConfig(log_conf)
logger = logging.getLogger()

# HTTP2 Header decoder
decoder = Decoder()

# Change INPUT_CONFIG to your pcap file's name and server/client's IP address
INPUT_CONFIG = {
    "pcap": "./pcap-sample/http2-h2c.pcap",
    "client": "10.9.0.2",
    "server": "139.162.123.134",
}
pcap_file = INPUT_CONFIG["pcap"]
client_ip = INPUT_CONFIG["client"]
server_ip = INPUT_CONFIG["server"]

logger.debug("Input config: {0}".format(INPUT_CONFIG))
# Change STREAM_NUMBER to the stream number you want to follow.
# STREAM_NUMBER = 0
# Switching protocol check
SWITCHING_PRTOCOL_TXT = "HTTP/1.1 101 Switching Protocols"

# Check if file exists
if not os.path.exists(pcap_file):
    logger.error("{0} doesn't exist".format(pcap_file))
    sys.exit(1)
# open the pcap file, filtered for a single TCP stream
cap = pyshark.FileCapture(pcap_file)

"""
# --------------------------------------
# Experimental code: not used right now
# --------------------------------------
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
"""

# server_config = H2Configuration(client_side=False)
# client_config = H2Configuration(client_side=True)
# server = H2Connection(config=server_config)
# client = H2Connection(config=client_config)
logger.debug("Initializing server/client HTTP2 buffers...")
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
        pkt_layers = str(curr_pkt.layers)
        logger.debug("Packet layers: {0}".format(pkt_layers))
        if "HTTP2" in pkt_layers:
            logger.debug("HTTP2 layer in current packet...")
            tmp_data = curr_pkt.tcp.payload.encode()
            h_list = [e for e in tmp_data.decode("utf-8").split(":")]
            tdata = "".join(h_list)
            byte_data = bytes.fromhex(tdata)
            logger.debug("Data in hex format:\n\n{0}\n".format(byte_data))
            try:
                byte_data_str = byte_data.decode("utf-8")
            except:
                byte_data_str = ""
            if SWITCHING_PRTOCOL_TXT in byte_data_str and curr_pkt.ip.dst == INPUT_CONFIG["client"]:
                # client.initiate_upgrade_connection()
                # print(client.data_to_send())
                logger.debug("HTTP2 upgrade response detected... ignoring this pkt.")
                curr_pkt = cap.next()
                continue
            # print([curr_pkt.ip.dst, byte_data], type(byte_data))
            logger.debug("Expected IPs: {0}/{1}, Pkt dst IP: {2}".format(server_ip, client_ip, curr_pkt.ip.dst))
            if curr_pkt.ip.dst == client_ip:
                # events = client.receive_data(byte_data)
                # print(events)
                logger.debug("Curr pkt is packet received by client")
                client_buffer.add_data(byte_data)
                # print(client_buffer.data)
                logger.debug("[client] Parsing HTTP2 packets...")
                for event in client_buffer:
                    # print("Client event: {0}".format(event))
                    client_events.append(event)
            elif curr_pkt.ip.dst == server_ip:
                # print("here")
                # events = server.receive_data(byte_data)
                # print(events)
                logger.debug("Curr pkt is packet received by server")
                server_buffer.add_data(byte_data)
                logger.debug("[server] Parsing HTTP2 packets...")
                for event in server_buffer:
                    # print("Server event: {0}".format(event))
                    server_events.append(event)
            else:
                logger.error(
                    "Pkt dst IP: {0} didn't match either IPs: {1}/{2}".format(curr_pkt.ip.dst, server_ip, client_ip)
                )
        logger.debug("Moving on to next packet...")
        curr_pkt = cap.next()
    except StopIteration:
        break

for event in client_events:
    logger.info("Client event: {0}, streamid: {1}".format(event, event.stream_id))
    if isinstance(event, HeadersFrame):
        logger.info("Client headers: {0}".format(decoder.decode(event.data)))
    if isinstance(event, DataFrame):
        logger.info("Client received data: {0}".format(event.data.decode("utf-8")))

for event in client_events:
    logger.info("Server event: {0}, streamid: {1}".format(event, event.stream_id))
    if isinstance(event, HeadersFrame):
        logger.info("Server headers: {0}".format(decoder.decode(event.data)))
    if isinstance(event, DataFrame):
        logger.info("Server received data: {0}".format(event.data.decode("utf-8")))
