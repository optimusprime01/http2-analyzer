# http2-analyzer
How to try this:

1. Setup python in your computer. Python 3.x.
2. Install hyper: `pip3 install hyper`. This will install hyper-h2 and hpack which is what the script uses.
3. Install pyshark: `pip3 install pyshark`. This is for reading the pcap file. 
3. Run the script: `python h2-pyshark.pcap`. It parses a sample pcap file in `pcap-sample` dir.
   Make sure you have the `logging.json` present in the same dir as the script.


# References:
1. [Logging dict config example](https://stackoverflow.com/questions/7507825/where-is-a-complete-example-of-logging-config-dictconfig)