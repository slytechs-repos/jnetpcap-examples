/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnet.jnetpcap.example;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;

import com.slytechs.jnet.jnetpcap.NetPcap;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.link.Ethernet;
import com.slytechs.jnet.protocol.core.network.Ip4;
import com.slytechs.jnet.protocol.core.network.Ip4RouterAlertOption;
import com.slytechs.jnet.protocol.core.transport.Tcp;
import com.slytechs.jnet.protocol.meta.PacketFormat;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Example1_CapturePacketsAndPrintHeaders {
	/**
	 * Bootstrap the example.
	 *
	 * @param args ignored
	 * @throws PcapException         any pcap exceptions
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public static void main(String[] args) throws PcapException, FileNotFoundException, IOException {
		new Example1_CapturePacketsAndPrintHeaders().main();
	}

	/**
	 * Example instance
	 * 
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	void main() throws PcapException, FileNotFoundException, IOException {
		/* Pcap capture file to read */
		final String PCAP_FILE = "pcaps/HTTP.cap";

		/* Make sure we have a compatible Pcap runtime installed */
		Pcap.checkPcapVersion(Pcap.VERSION);

		/*
		 * Automatically close Pcap resource when done and checks the client and
		 * installed runtime API versions to ensure they are compatible.
		 */
		try (NetPcap pcap = NetPcap.offline(PCAP_FILE)) {

			/* Set a pretty print formatter to toString() method */
			pcap.setPacketFormatter(new PacketFormat());

			/* Number of packets to capture */
			final int PACKET_COUNT = 10;

			/* Create protocol headers and reuse inside the dispatch handler */
			final Ethernet ethernet = new Ethernet();
			final Ip4 ip4 = new Ip4();
			final Tcp tcp = new Tcp();
			final Ip4RouterAlertOption router = new Ip4RouterAlertOption();

			/* Capture packets and access protocol headers */
			pcap.dispatchPacket(PACKET_COUNT, (String user, Packet packet) -> {

				// If present, printout ethernet header
				if (packet.hasHeader(ethernet))
					System.out.println(ethernet);

				// If present, printout ip4 header
				if (packet.hasHeader(ip4))
					System.out.println(ip4);

				// If present, printout IPv4.router header extension
				if (packet.hasHeader(ip4) && ip4.hasOption(router))
					System.out.println(router);

				// If present, printout tcp header
				if (packet.hasHeader(tcp))
					System.out.println(tcp);

			}, "Example2 - Hello World");
		}
	}
}
