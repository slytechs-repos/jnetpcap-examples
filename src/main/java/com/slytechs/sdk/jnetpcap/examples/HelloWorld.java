/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.jnetpcap.examples;

import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.jnetpcap.api.NetPcap;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

/**
 * Hello World
 *
 * <p>
 * The simplest possible jNetPcap program. Reads packets from a pcap file and
 * prints the source and destination address of every TCP/IPv4 packet.
 * </p>
 *
 * <p>
 * Demonstrates the three core concepts of jNetPcap:
 * </p>
 * <ul>
 * <li><strong>Zero-allocation headers</strong> — {@link Ip4} and {@link Tcp}
 *     are allocated once outside the loop and reused for every packet. No
 *     per-packet heap allocation occurs on the hot path.</li>
 * <li><strong>{@code hasHeader()} binding</strong> — binds the pre-allocated
 *     header to the current packet's data in place. Returns {@code true} if
 *     the protocol is present, {@code false} otherwise.</li>
 * <li><strong>Offline file reading</strong> — {@link NetPcap#openOffline}
 *     opens a pcap or pcapng file and returns a handle ready for
 *     dispatch.</li>
 * </ul>
 *
 * <h2>Expected Output</h2>
 * <pre>
 * 192.168.1.140:57678 → 174.143.213.184:80
 * 174.143.213.184:80 → 192.168.1.140:57678
 * ...
 * </pre>
 *
 * <h2>Run</h2>
 * <pre>
 * mvn compile exec:java -Dexec.mainClass="com.slytechs.sdk.jnetpcap.examples.HelloWorld"
 * </pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see NetPcap#openOffline(String)
 * @see com.slytechs.sdk.protocol.core.Packet#hasHeader
 */
public class HelloWorld {

	/**
	 * Program entry point.
	 *
	 * @param args command-line arguments (not used)
	 * @throws PcapException if the pcap file cannot be opened or read
	 */
	public static void main(String[] args) throws PcapException {

		// Allocate headers once — reused across all packets, zero GC pressure
		Ip4 ip4 = new Ip4();
		Tcp tcp = new Tcp();

		try (var pcap = NetPcap.openOffline("pcaps/capture.pcap")) {

			pcap.loop(-1, packet -> {

				// hasHeader() binds the header to packet data if the protocol is present
				if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
					System.out.printf("%s:%d → %s:%d%n",
							ip4.src(), tcp.srcPort(),
							ip4.dst(), tcp.dstPort());
				}
			});
		}
	}
}