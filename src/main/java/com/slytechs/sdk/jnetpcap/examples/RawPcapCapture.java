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

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Duration;

import com.slytechs.sdk.jnetpcap.Pcap;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.jnetpcap.PcapHeader;
import com.slytechs.sdk.jnetpcap.internal.PcapHeaderABI;

/**
 * Example 20: Raw Pcap Capture
 * 
 * Demonstrates using the low-level Pcap class directly without the NetPcap
 * wrapper or protocol dissection. This provides: - Direct 1:1 mapping to
 * libpcap functions - Raw MemorySegment access to packet data - Maximum
 * performance (no dissection overhead)
 * 
 * Use this approach when: - You don't need protocol dissection - You're
 * implementing custom parsing - You need the lowest possible overhead
 * 
 * The Pcap class is in package: com.slytechs.sdk.jnetpcap
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class RawPcapCapture {

	public static void main(String[] args) throws PcapException {
		new RawPcapCapture().run();
	}

	public void run() throws PcapException {
		String device = Pcap.findAllDevs()
				.stream()
				.filter(d -> d.isUp() && !d.isLoopback())
				.findFirst()
				.map(d -> d.name())
				.orElseThrow(() -> new IllegalStateException("No suitable network interface found"));

		System.out.printf("Raw capture on device: %s%n", device);
		System.out.println("Press Ctrl+C to stop...");
		System.out.println();

		// Use low-level Pcap class directly
		try (Pcap pcap = Pcap.create(device)) {

			pcap.setSnaplen(65535)
					.setPromisc(true)
					.setTimeout((int) Duration.ofMillis(100).toMillis())
					.activate();

			// Optional: set filter at raw level
//            pcap.setFilter("ip");

			final long[] stats = {
					0,
					0
			}; // [packets, bytes]

			// Abstract Binary Interface - properly interprets binary pcap header
			// Endianness, C-struct packed (16-bytes) vs padded (24-bytes on x64)
			PcapHeaderABI abi = pcap.getPcapHeaderABI();

			// Raw dispatch - receives PcapHeader and MemorySegment
			pcap.loop(100, (String _, MemorySegment header, MemorySegment data) -> {

				stats[0]++;
				stats[1] += PcapHeader.captureLength(header);

				// Access raw packet bytes
				int capLen = abi.captureLength(header);
				int wireLen = abi.wireLength(header);
				long tsSec = abi.tvSec(header);
				long tsUsec = abi.tvUsec(header);

				System.out.printf("#%d: ts=%d.%06d wire=%d cap=%d%n",
						stats[0], tsSec, tsUsec, wireLen, capLen);

				// Manual Ethernet parsing example
				if (capLen >= 14) {
					// Ethernet header: dst(6) + src(6) + type(2)
					printEthernetHeader(data);
				}

				// Manual IP parsing example
				if (capLen >= 34) {
					short etherType = data.get(ValueLayout.JAVA_SHORT, 12);
					if (etherType == 0x0800 || etherType == 0x0008) { // IPv4 (handle byte order)
						printIpv4Header(data);
					}
				}

				System.out.println();
			}, "");

			System.out.println("=== Summary ===");
			System.out.printf("Packets: %d%n", stats[0]);
			System.out.printf("Bytes: %d%n", stats[1]);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Manual Ethernet header parsing from raw memory.
	 */
	private void printEthernetHeader(MemorySegment data) {
		// Destination MAC (bytes 0-5)
		StringBuilder dstMac = new StringBuilder();
		for (int i = 0; i < 6; i++) {
			if (i > 0)
				dstMac.append(":");
			dstMac.append(String.format("%02x", data.get(ValueLayout.JAVA_BYTE, i) & 0xFF));
		}

		// Source MAC (bytes 6-11)
		StringBuilder srcMac = new StringBuilder();
		for (int i = 6; i < 12; i++) {
			if (i > 6)
				srcMac.append(":");
			srcMac.append(String.format("%02x", data.get(ValueLayout.JAVA_BYTE, i) & 0xFF));
		}

		// EtherType (bytes 12-13, big-endian)
		int etherType = ((data.get(ValueLayout.JAVA_BYTE, 12) & 0xFF) << 8) |
				(data.get(ValueLayout.JAVA_BYTE, 13) & 0xFF);

		System.out.printf("  Ethernet: %s → %s [0x%04X]%n", srcMac, dstMac, etherType);
	}

	/**
	 * Manual IPv4 header parsing from raw memory.
	 */
	private void printIpv4Header(MemorySegment data) {
		int offset = 14; // After Ethernet header

		// Version + IHL (byte 0)
		byte versionIhl = data.get(ValueLayout.JAVA_BYTE, offset);
		int version = (versionIhl >> 4) & 0x0F;
		int ihl = versionIhl & 0x0F;

		if (version != 4)
			return;

		// TTL (byte 8)
		int ttl = data.get(ValueLayout.JAVA_BYTE, offset + 8) & 0xFF;

		// Protocol (byte 9)
		int protocol = data.get(ValueLayout.JAVA_BYTE, offset + 9) & 0xFF;

		// Source IP (bytes 12-15)
		String srcIp = String.format("%d.%d.%d.%d",
				data.get(ValueLayout.JAVA_BYTE, offset + 12) & 0xFF,
				data.get(ValueLayout.JAVA_BYTE, offset + 13) & 0xFF,
				data.get(ValueLayout.JAVA_BYTE, offset + 14) & 0xFF,
				data.get(ValueLayout.JAVA_BYTE, offset + 15) & 0xFF);

		// Destination IP (bytes 16-19)
		String dstIp = String.format("%d.%d.%d.%d",
				data.get(ValueLayout.JAVA_BYTE, offset + 16) & 0xFF,
				data.get(ValueLayout.JAVA_BYTE, offset + 17) & 0xFF,
				data.get(ValueLayout.JAVA_BYTE, offset + 18) & 0xFF,
				data.get(ValueLayout.JAVA_BYTE, offset + 19) & 0xFF);

		String protoName = switch (protocol) {
		case 1 -> "ICMP";
		case 6 -> "TCP";
		case 17 -> "UDP";
		default -> String.valueOf(protocol);
		};

		System.out.printf("  IPv4: %s → %s [%s] TTL=%d%n", srcIp, dstIp, protoName, ttl);
	}
}