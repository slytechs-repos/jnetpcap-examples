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
package com.slytechs.sdk.jnetpcap.examples;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Instant;

import org.jnetpcap.BpFilter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.util.PcapUtils;

/**
 * Example showing how to capture offline packets and dispatch to a user packet
 * handler of type {@code PcapHandler.OfMemorySegment}. The example checks the
 * API version for compatibility, sets a packet filter and dispatches 10 packets
 * to low level user packet handler with memory pointers to packet header and
 * data.
 */
public class Example3_FilterRawPackets {

	/**
	 * Bootstrap the example.
	 *
	 * @param args ignored
	 * @throws PcapException any pcap exceptions
	 */
	public static void main(String[] args) throws PcapException {
		new Example3_FilterRawPackets().main();
	}

	/** Example instance */
	void main() throws PcapException {
		/* Pcap capture file to read */
		final String PCAP_FILE = "pcaps/HTTP.cap";

		/* Make sure we have a compatible Pcap runtime installed */
		Pcap.checkPcapVersion(Pcap.VERSION);

		/* Automatically close Pcap resource when done */
		try (Pcap pcap = Pcap.openOffline(PCAP_FILE)) {

			/* Compile packet filter to capture TCP packets only */
			BpFilter filter = pcap.compile("tcp", true);

			/* Set our packet filter and start the capture */
			pcap.setFilter(filter);

			/* Number of packets to capture */
			final int PACKET_COUNT = 10;

			/* Send packets to handler. The generic user parameter can be of any type. */
			pcap.dispatch(PACKET_COUNT, this::nextPacket, "Example 3");
		}
	}

	/** Our packet handler */
	void nextPacket(String user, MemorySegment hdr, MemorySegment packet) {

		PcapHeader header = new PcapHeader(hdr);

		// MemorySegment contains packet data, accessible using new java's FF API
		byte[] array = packet
				.toArray(ValueLayout.JAVA_BYTE);

		System.out.printf("%s: timestamp=%s, wirelen=%-4d caplen=%-4d %s%n",
				user,
				Instant.ofEpochMilli(header.toEpochMilli()),
				header.wireLength(),
				header.captureLength(),
				PcapUtils.toHexCurleyString(array, 0, 6));
	}
}
