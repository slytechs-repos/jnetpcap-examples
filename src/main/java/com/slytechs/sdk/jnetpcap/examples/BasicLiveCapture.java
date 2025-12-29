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

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.sdk.jnetpcap.PcapException;

/**
 * Example 1: Basic Live Capture
 *
 * Demonstrates the simplest possible live packet capture using the modern
 * two-stage pattern: 1. create() - obtain a configurable handle 2. activate() -
 * start capture with default settings
 *
 * This example opens the first available network interface, captures packets
 * indefinitely, and prints basic packet information (timestamp, wire length,
 * captured length). It uses an infinite loop (-1) and can be stopped with
 * Ctrl+C.
 *
 * No BPF filter, no ProtocolStack - pure minimal capture.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class BasicLiveCapture {

	public static void main(String[] args) throws IllegalStateException, PcapException {
		new BasicLiveCapture().run();
	}

	public void run() throws IllegalStateException, PcapException {

		// Use the first available network interface
		String device = NetPcap.findAllDevs()
				.stream()
				.filter(d -> d.isUp() && !d.isLoopback())
				.findFirst()
				.map(d -> d.name())
				.orElseThrow(() -> new IllegalStateException("No suitable network interface found"));

		System.out.printf("Capturing on device: %s%n", device);
		System.out.println("Press Ctrl+C to stop...");

		try (NetPcap pcap = NetPcap.create(device)) {

			// Minimal configuration - use defaults (snaplen=65535, promisc=false,
			// timeout=1s)
			pcap.activate();

			// Infinite loop with simple packet consumer
			pcap.loop(-1, packet -> {
				System.out.printf("[%s] wire=%d cap=%d%n",
						packet.timestampInfo(),
						packet.wireLength(),
						packet.captureLength());
			});

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}