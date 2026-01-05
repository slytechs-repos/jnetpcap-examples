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

import java.util.HashMap;
import java.util.Map;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.ip.Ip6;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;
import com.slytechs.sdk.protocol.tcpip.udp.Udp;

/**
 * Example 4: Packet Counter by Protocol
 * 
 * Demonstrates protocol dissection with PacketSettings and the zero-allocation
 * hasHeader() pattern to count packets by protocol type.
 * 
 * Uses the user context parameter in dispatch() to pass a mutable stats map
 * to the packet handler - avoiding closure overhead.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class PacketCounter {

    private static final String DEFAULT_FILE = "pcaps/HTTP.cap";

    public static void main(String[] args) throws PcapException {
        String filename = args.length > 0 ? args[0] : DEFAULT_FILE;
        new PacketCounter().run(filename);
    }

    public void run(String filename) throws PcapException {
        NetPcap.activateLicense();

        System.out.printf("Counting protocols in: %s%n", filename);

        // Enable protocol dissection
        PacketSettings settings = new PacketSettings()
                .dissect();

        // Pre-allocate headers (reused across all packets - zero allocation)
        Ip4 ip4 = new Ip4();
        Ip6 ip6 = new Ip6();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();

        // Statistics counters
        Map<String, Long> stats = new HashMap<>();
        stats.put("total", 0L);
        stats.put("ipv4", 0L);
        stats.put("ipv6", 0L);
        stats.put("tcp", 0L);
        stats.put("udp", 0L);
        stats.put("other", 0L);

        try (NetPcap pcap = NetPcap.openOffline(filename, settings)) {

            // Use dispatch with user context to avoid closure allocation
            pcap.loop(-1, (counters, packet) -> {
                counters.merge("total", 1L, Long::sum);

                // Layer 3 - Network
                if (packet.hasHeader(ip4)) {
                    counters.merge("ipv4", 1L, Long::sum);
                } else if (packet.hasHeader(ip6)) {
                    counters.merge("ipv6", 1L, Long::sum);
                }

                // Layer 4 - Transport
                if (packet.hasHeader(tcp)) {
                    counters.merge("tcp", 1L, Long::sum);
                } else if (packet.hasHeader(udp)) {
                    counters.merge("udp", 1L, Long::sum);
                } else {
                    counters.merge("other", 1L, Long::sum);
                }
            }, stats);

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        // Print results
        System.out.println();
        System.out.println("=== Protocol Statistics ===");
        System.out.printf("Total packets: %,d%n", stats.get("total"));
        System.out.println();
        System.out.println("Network Layer:");
        System.out.printf("  IPv4:  %,d (%.1f%%)%n", stats.get("ipv4"), 
                percent(stats.get("ipv4"), stats.get("total")));
        System.out.printf("  IPv6:  %,d (%.1f%%)%n", stats.get("ipv6"), 
                percent(stats.get("ipv6"), stats.get("total")));
        System.out.println();
        System.out.println("Transport Layer:");
        System.out.printf("  TCP:   %,d (%.1f%%)%n", stats.get("tcp"), 
                percent(stats.get("tcp"), stats.get("total")));
        System.out.printf("  UDP:   %,d (%.1f%%)%n", stats.get("udp"), 
                percent(stats.get("udp"), stats.get("total")));
        System.out.printf("  Other: %,d (%.1f%%)%n", stats.get("other"), 
                percent(stats.get("other"), stats.get("total")));
    }

    private double percent(long value, long total) {
        return total > 0 ? (value * 100.0) / total : 0;
    }
}