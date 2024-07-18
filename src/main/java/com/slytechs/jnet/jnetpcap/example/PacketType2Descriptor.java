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

import org.jnetpcap.PcapException;

import com.slytechs.jnet.jnetpcap.NetPcap;
import com.slytechs.jnet.jnetruntime.time.Timestamp;
import com.slytechs.jnet.protocol.Packet;

/**
 * Example showing how to capture offline packets and dispatch to a user packet
 * handler of type {@code PcapProHandler.OfPacket}.
 */
public class PacketType2Descriptor {

	/**
	 * Bootstrap the example.
	 *
	 * @param args ignored
	 * @throws PcapException any pcap exceptions
	 */
	public static void main(String[] args) throws PcapException {
		new PacketType2Descriptor().main();
	}

	/** Example instance */
	void main() throws PcapException {
		/* Pcap capture file to read */
		final String PCAP_FILE = "pcaps/HTTP.cap";

		/* Automatically close Pcap resource when done */
		try (NetPcap pcap = NetPcap.openOffline(PCAP_FILE)) { // Pro API

			/* Number of packets to capture */
			final int PACKET_COUNT = 10;

			/* Send packets to handler. The generic user parameter can be of any type. */
			pcap.loop(PACKET_COUNT, (String user, Packet packet) -> { // Pro API
				System.out.printf("%s: %03d: caplen=%-,5d ts=%s%n",
						user,
						packet.descriptor().frameNo(),
						packet.captureLength(),
						new Timestamp(packet.timestamp(), packet.timestampUnit()));

			}, "Example2");
		}
	}
}
