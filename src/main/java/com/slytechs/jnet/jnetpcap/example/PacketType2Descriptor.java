/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnet.jnetpcap.example;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.jnetpcap.PcapException;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.jnet.platform.api.util.time.Timestamp;
import com.slytechs.jnet.protocol.api.packet.Packet;

/**
 * Example showing how to capture offline packets and dispatch to a user packet
 * handler of type {@code PcapProHandler.OfPacket}.
 */
public class PacketType2Descriptor {

	/**
	 * Bootstrap the example.
	 *
	 * @param args ignored
	 * @throws PcapException         any pcap exceptions
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public static void main(String[] args) throws PcapException, FileNotFoundException, IOException {
		new PacketType2Descriptor().main();
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

		/* Automatically close Pcap resource when done */
		try (NetPcap pcap = NetPcap.offline(PCAP_FILE)) {

			/* Number of packets to capture */
			final int PACKET_COUNT = 10;

			/* Send packets to handler. The generic user parameter can be of any type. */
			pcap.dispatchPacket(PACKET_COUNT, (String user, Packet packet) -> {
				System.out.printf("%s: %03d: caplen=%-,5d ts=%s%n",
						user,
						packet.descriptor().frameNo(),
						packet.captureLength(),
						new Timestamp(packet.timestamp(), packet.timestampUnit()));

			}, "Example2");
		}
	}
}
