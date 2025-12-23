/*
* Copyright 2024 Sly Technologies Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package com.slytechs.sdk.jnetpcap.examples;

import java.io.FileNotFoundException;
import java.io.IOException;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

/**
 * Example demonstrating basic packet capture and header inspection using
 * JNetPcap. This example shows how to: 1. Open a pcap file 2. Configure packet
 * formatting 3. Process a limited number of packets 4. Extract and display
 * various protocol headers
 * 
 * Example output from the last packet:
 * 
 * <pre>
* Ethernet:  + Ethernet II, src: Actionte_2f:47:87 dst: ASUSTeKC_b3:01:84 offset=0 length=14
* Ethernet:  Destination Address = ASUSTeKC_b3:01:84 (00:1D:60:B3:01:84)
* Ethernet:      Source Address = Actionte_2f:47:87 (00:26:62:2F:47:87)  
* Ethernet:             Type = IPv4 (0x0800)
* 
* IPv4:      + Internet Protocol Version 4, offset=14, length=20
* IPv4:              Version = 4 
* IPv4:                      0100 .... = Version: 4
* IPv4:        Header Length = 5 [5*4 = 20 bytes]
* IPv4:                      .... 0101 = Header Length: 20 bytes (5)
* IPv4:        Traffic class = 0x00 [DSCP: CS0, ECN: Not-ECT]
* IPv4:                      0000 00.. = Differentiated Services Codepoint: Default (0)
* IPv4:                      .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
* IPv4:       Total Length = 1500 bytes
* IPv4:    Identification = 0x27E0 (10208)
* IPv4:            Flags = 0x2 [DF]
* IPv4:                      010. .... .... .... = Flags: 0x2 (•D•)
* IPv4:    Fragment Offset = 0 [0*8 = 0 bytes]]
* IPv4:                      ...0 0000 0000 0000 = Fragment Offset: 0
* IPv4:        Time to Live = 251
* IPv4:           Protocol = TCP (6)
* IPv4:    Header Checksum = 0x0bbf
* IPv4:     Source Address = 174.143.213.184
* IPv4: Destination Address = 192.168.1.140
* 
* TCP:       + Transmission Control Protocol, offset=34, length=40
* TCP:           destination = 57678
* TCP:                source = 80
* TCP:    Sequence Number (raw) = 3344083161
* TCP: Acknowledgment Number (raw) = 2387614088
* TCP:        Header Length = 40 bytes (8)
* TCP:               Flags = 0x010 (ACK) [... ...A ....]
* TCP:              Window = 108
* TCP:            Checksum = 0xDE29
* TCP:       Urgent Pointer = 0
 * </pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Example1_CapturePacketsAndPrintHeaders {

	/**
	 * Entry point that creates and runs an instance of the example.
	 *
	 * @param args command line arguments (not used)
	 * @throws PcapException         if there's an error during packet capture
	 * @throws IOException           if there's an error reading the pcap file
	 * @throws FileNotFoundException if the pcap file cannot be found
	 */
	public static void main(String[] args) throws PcapException, FileNotFoundException, IOException {
		new Example1_CapturePacketsAndPrintHeaders().main();
	}

	/**
	 * Core example implementation demonstrating packet capture and header
	 * inspection.
	 * 
	 * @throws PcapException         if there's an error during packet capture
	 * @throws IOException           if there's an error reading the pcap file
	 * @throws FileNotFoundException if the pcap file cannot be found
	 */
	void main() throws PcapException, FileNotFoundException, IOException {
		// Path to the pcap file containing HTTP traffic
		final String PCAP_FILE = "pcaps/HTTP.cap";

		// Verify JNetPcap version compatibility before proceeding
		NetPcap.checkVersion(NetPcap.VERSION);

		// Open the pcap file using try-with-resources to ensure proper cleanup
		try (NetPcap pcap = NetPcap.openOffline(PCAP_FILE)) {

			// Limit packet processing to first 10 packets for this example
			final int PACKET_COUNT = 1;

			// Initialize protocol headers once and reuse them for efficiency
			final Ethernet ethernet = new Ethernet();
			final Ip4 ip4 = new Ip4();
			final Tcp tcp = new Tcp();

			// Process packets and inspect headers using a lambda callback
			pcap.dispatch(PACKET_COUNT, (String user, Packet packet) -> {

				// Check and display Ethernet header if present
				if (packet.hasHeader(ethernet))
					System.out.println(ethernet);

				// Check and display IPv4 header if present
				if (packet.hasHeader(ip4))
					System.out.println(ip4);

				// Check and display TCP header if present
				if (packet.hasHeader(tcp))
					System.out.println(tcp);

			}, "Example1 - Packet Header Inspection");
		}
	}
}