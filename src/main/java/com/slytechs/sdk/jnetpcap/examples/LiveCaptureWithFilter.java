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

import java.time.Duration;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.sdk.jnetpcap.PcapException;

/**
 * Example 2: Live Capture with Filter and Configuration
 * 
 * Demonstrates the two-stage capture pattern with full configuration:
 * - Snaplen: capture only first 128 bytes (headers only)
 * - Promiscuous mode: see all traffic on network segment
 * - Timeout: 100ms read timeout for responsive dispatch
 * - Immediate mode: disable buffering for low latency
 * - BPF filter: capture only TCP traffic on ports 80 or 443
 * 
 * Uses dispatch() which respects timeout, unlike loop() which blocks.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class LiveCaptureWithFilter {

    public static void main(String[] args) throws PcapException {
        new LiveCaptureWithFilter().run();
    }

    public void run() throws PcapException {
        NetPcap.activateLicense();

        String device = NetPcap.findAllDevs()
                .stream()
                .filter(d -> d.isUp() && !d.isLoopback())
                .findFirst()
                .map(d -> d.name())
                .orElseThrow(() -> new IllegalStateException("No suitable network interface found"));

        System.out.printf("Capturing on device: %s%n", device);
        System.out.println("Filter: tcp port 80 or tcp port 443");
        System.out.println("Press Ctrl+C to stop...");

        try (NetPcap pcap = NetPcap.create(device)) {

            // Stage 1: Configure capture parameters (before activate)
            pcap.setSnaplen(128)                      // Headers only
                .setPromisc(true)                     // Promiscuous mode
                .setTimeout(Duration.ofMillis(100))  // 100ms timeout
                .setImmediateMode(true)              // Low latency
                .activate();

            // Stage 2: Post-activation configuration
            pcap.setFilter("tcp port 80 or tcp port 443");

            // Capture loop using dispatch (respects timeout)
            int packetCount = 0;
            while (true) {
                int received = pcap.dispatch(100, packet -> {
                    System.out.printf("[%s] %d bytes%n",
                            packet.timestampInfo(),
                            packet.captureLength());
                });

                if (received > 0) {
                    packetCount += received;
                    System.out.printf("--- Batch: %d packets (total: %d) ---%n", 
                            received, packetCount);
                }
                // received == 0 means timeout, continue loop
                // received == -1 means error
                // received == -2 means breakloop called
                if (received < 0) break;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}