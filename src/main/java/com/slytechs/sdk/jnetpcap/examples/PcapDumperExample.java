/*
 * Copyright 2005-2025 Sly Technologies Inc.
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

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.sdk.jnetpcap.PcapDumper;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

/**
 * Example 16: Pcap Dumper
 * 
 * Demonstrates writing captured packets to a pcap file using PcapDumper. Useful
 * for: - Recording traffic for later analysis - Filtering and saving specific
 * packets - Creating test captures
 * 
 * This example captures TCP SYN packets and saves them to a file.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class PcapDumperExample {

	private static final String OUTPUT_FILE = "syn_packets.pcap";
	private static final int CAPTURE_COUNT = 100;

	public static void main(String[] args) throws PcapException {
		new PcapDumperExample().run();
	}

	public void run() throws PcapException {
		String device = NetPcap.findAllDevs()
				.stream()
				.filter(d -> d.isUp() && !d.isLoopback())
				.findFirst()
				.map(d -> d.name())
				.orElseThrow(() -> new IllegalStateException("No suitable network interface found"));

		System.out.printf("Capturing TCP SYN packets on: %s%n", device);
		System.out.printf("Output file: %s%n", OUTPUT_FILE);
		System.out.printf("Target count: %d packets%n", CAPTURE_COUNT);
		System.out.println();

		PacketSettings settings = new PacketSettings()
				.dissect();

		Ip4 ip4 = new Ip4();
		Tcp tcp = new Tcp();

		AtomicInteger synCount = new AtomicInteger();
		AtomicInteger totalCount = new AtomicInteger();

		try (NetPcap pcap = NetPcap.create(device, settings)) {

			pcap.setSnaplen(128)
					.setPromisc(true)
					.setTimeout(Duration.ofMillis(100))
					.activate();

			pcap.setFilter("tcp");

			// Open dumper for writing
			try (PcapDumper dumper = pcap.dumpOpen(OUTPUT_FILE)) {

				System.out.println("Capturing...");

				while (synCount.get() < CAPTURE_COUNT) {
					pcap.dispatch(100, packet -> {
						totalCount.incrementAndGet();

						// Check for TCP SYN
						if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
							if (tcp.isSyn() && !tcp.isAck()) {
								// Write packet to file
								try {
									MemorySegment hdr = packet.descriptor().boundMemory().segment();
									MemorySegment pkt = packet.boundMemory().segment();
									dumper.dump(hdr, pkt);

								} catch (IOException e) {
									e.printStackTrace();
									return;
								}

								int count = synCount.incrementAndGet();
								System.out.printf("[%d] SYN: %s:%d → %s:%d%n",
										count,
										ip4.src(), tcp.srcPort(),
										ip4.dst(), tcp.dstPort());
							}
						}
					});
				}

				// Flush to ensure all packets are written
				dumper.flush();
			}

		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		System.out.println();
		System.out.println("=== Capture Complete ===");
		System.out.printf("Total packets seen: %,d%n", totalCount.get());
		System.out.printf("SYN packets saved: %,d%n", synCount.get());
		System.out.printf("Output file: %s%n", OUTPUT_FILE);
	}
}