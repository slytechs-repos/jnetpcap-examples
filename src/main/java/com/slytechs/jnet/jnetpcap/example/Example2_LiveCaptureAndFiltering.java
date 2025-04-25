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
package com.slytechs.jnet.jnetpcap.example;

import java.io.IOException;
import java.util.List;

import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.jnet.platform.api.common.NotFound;
import com.slytechs.jnet.platform.api.util.MemoryUnit;
import com.slytechs.jnet.protocol.api.common.Packet;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4;
import com.slytechs.jnet.protocol.tcpip.tcp.Tcp;

/**
 * Example demonstrating live packet capture and filtering capabilities of
 * JNetPcap. This example shows how to: 1. List and select network devices 2.
 * Configure capture parameters 3. Apply filters 4. Process live traffic using
 * packet handlers
 *
 * Example output:
 * 
 * <pre>
 * Available devices:
 * - enp15s0
 * - any
 * - lo
 * - enp13s0f0
 * - enp13s0f1
 * - wlp16s0
 * - bluetooth0
 * - bluetooth-monitor
 * - nflog
 * - nfqueue
 * - dbus-system
 * - dbus-session
 * 
 * Capturing on interface: enp15s0
 * Press Ctrl+C to stop
 * 
 * Source IP: 104.244.42.130
 * Dest IP: 192.168.1.232
 * Source Port: 443
 * Dest Port: 35788
 * 
 * Source IP: 192.168.1.232
 * Dest IP: 104.244.42.130
 * Source Port: 35788
 * Dest Port: 443
 * </pre>
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Example2_LiveCaptureAndFiltering {

	public static void main(String[] args) throws PcapException, IOException, NotFound {
		new Example2_LiveCaptureAndFiltering().main();
	}

	void main() throws PcapException, IOException, NotFound {
		// List all available network devices
		List<PcapIf> devices = NetPcap.listPcapDevices();

		System.out.println("Available devices:");
		for (PcapIf device : devices) {
			System.out.printf("  - %s%n", device.name());
		}
		System.out.println();

		// Create live capture on default interface with configuration
		try (NetPcap pcap = NetPcap.live()) {

			// Configure capture parameters
			pcap.setBufferSize(64, MemoryUnit.MEGABYTES) // Capture buffer size
					.setSnaplen(2048) // Snapshot length
					.setTimeout(10_000) // Read timeout
					.setPromiscuous(true); // Promiscuous mode

			// Must activate before setting filter
			pcap.activate();

			// Set a BPF filter for TCP traffic only
			pcap.setFilter("tcp");

			// Configure pretty print formatting
			pcap.setPacketFormatter(new PacketFormat());

			System.out.printf("Capturing on interface: %s%n", pcap.name());
			System.out.println("Processing 100 packets...\n");

			// Initialize protocol headers once for reuse
			final Ip4 ip4 = new Ip4();
			final Tcp tcp = new Tcp();

			// Dispatch 100 packets using PacketHandler.OfPacket
			pcap.dispatchPacket(100, (String user, Packet packet) -> {

				// Check and display IPv4 header if present
				if (packet.hasHeader(ip4)) {
					System.out.printf("Source IP: %s%n", ip4.srcAsAddress());
					System.out.printf("Dest IP: %s%n", ip4.dstAsAddress());
				}

				// Check and display TCP header if present
				if (packet.hasHeader(tcp)) {
					System.out.printf("Source Port: %d%n", tcp.source());
					System.out.printf("Dest Port: %d%n", tcp.destination());
				}

				System.out.println();
			}, "Example2"); // User data string passed through to handler
		}
	}
}