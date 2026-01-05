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
 * Example 3: Offline File Reading
 * 
 * Demonstrates reading packets from pcap and pcapng capture files.
 * Supports both legacy pcap format and modern pcapng format.
 * 
 * Uses loop(-1) to process all packets in the file until EOF.
 * The loop returns the total count when file is exhausted.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class OfflineFileReading {

    private static final String DEFAULT_FILE = "pcaps/HTTP.cap";

    public static void main(String[] args) throws PcapException {
        String filename = args.length > 0 ? args[0] : DEFAULT_FILE;
        new OfflineFileReading().run(filename);
    }

    public void run(String filename) throws PcapException {
        NetPcap.activateLicense();

        System.out.printf("Reading file: %s%n", filename);

        long startTime = System.currentTimeMillis();
        long totalBytes = 0;
        int packetCount = 0;

        try (NetPcap pcap = NetPcap.openOffline(filename)) {

            // Print file info
            System.out.printf("Link type: %s%n", pcap.datalink());
            System.out.printf("Snaplen: %d%n", pcap.snapshot());

            // Process all packets (-1 = until EOF)
            final long[] stats = new long[2]; // [count, bytes]
            
            pcap.loop(-1, packet -> {
                stats[0]++;
                stats[1] += packet.captureLength();

                // Print every 10000th packet for progress
                if (stats[0] % 10000 == 0) {
                    System.out.printf("  Processed %d packets...%n", stats[0]);
                }
            });

            packetCount = (int) stats[0];
            totalBytes = stats[1];

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        long elapsed = System.currentTimeMillis() - startTime;
        
        System.out.println();
        System.out.println("=== Summary ===");
        System.out.printf("Packets: %,d%n", packetCount);
        System.out.printf("Total bytes: %,d%n", totalBytes);
        System.out.printf("Time: %d ms%n", elapsed);
        
        if (elapsed > 0) {
            double pps = (packetCount * 1000.0) / elapsed;
            double mbps = (totalBytes * 8.0 / 1_000_000) / (elapsed / 1000.0);
            System.out.printf("Rate: %,.0f packets/sec%n", pps);
            System.out.printf("Throughput: %.2f Mbps%n", mbps);
        }
    }
}