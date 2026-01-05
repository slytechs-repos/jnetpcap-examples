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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

/**
 * Example 6: HTTP Traffic Analyzer
 * 
 * Captures live HTTP/HTTPS traffic and tracks connections by source IP.
 * Demonstrates:
 * - BPF filtering for specific ports
 * - Connection tracking with IP/port tuples
 * - TCP flag analysis (SYN for new connections)
 * - Statistics aggregation
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class HttpTrafficAnalyzer {

    public static void main(String[] args) throws PcapException {
        new HttpTrafficAnalyzer().run();
    }

    public void run() throws PcapException {
        String device = NetPcap.findAllDevs()
                .stream()
                .filter(d -> d.isUp() && !d.isLoopback())
                .findFirst()
                .map(d -> d.name())
                .orElseThrow(() -> new IllegalStateException("No suitable network interface found"));

        System.out.printf("Analyzing HTTP/HTTPS traffic on: %s%n", device);
        System.out.println("Press Ctrl+C to stop and see summary...");
        System.out.println();

        // Enable dissection
        PacketSettings settings = new PacketSettings()
                .dissect();

        // Pre-allocate headers
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();

        // Statistics tracking
        Map<String, AtomicLong> connectionsByIp = new ConcurrentHashMap<>();
        Map<String, AtomicLong> bytesByIp = new ConcurrentHashMap<>();
        AtomicLong totalPackets = new AtomicLong();
        AtomicLong totalBytes = new AtomicLong();
        AtomicLong synPackets = new AtomicLong();

        // Shutdown hook to print summary
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println();
            System.out.println("=== HTTP/HTTPS Traffic Summary ===");
            System.out.printf("Total packets: %,d%n", totalPackets.get());
            System.out.printf("Total bytes: %,d%n", totalBytes.get());
            System.out.printf("New connections (SYN): %,d%n", synPackets.get());
            System.out.println();
            System.out.println("Top Sources by Packets:");
            connectionsByIp.entrySet().stream()
                    .sorted((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()))
                    .limit(10)
                    .forEach(e -> System.out.printf("  %s: %,d packets, %,d bytes%n",
                            e.getKey(),
                            e.getValue().get(),
                            bytesByIp.getOrDefault(e.getKey(), new AtomicLong()).get()));
        }));

        try (NetPcap pcap = NetPcap.create(device, settings)) {

            pcap.setSnaplen(128)
                .setPromisc(true)
                .setTimeout(Duration.ofMillis(100))
                .activate();

            // Filter for HTTP (80) and HTTPS (443) traffic
            pcap.setFilter("tcp port 80 or tcp port 443");

            pcap.loop(-1, packet -> {
                if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
                    String srcIp = ip4.src().toString();
                    int srcPort = tcp.srcPort();
                    int dstPort = tcp.dstPort();
                    int len = packet.captureLength();

                    // Track statistics
                    totalPackets.incrementAndGet();
                    totalBytes.addAndGet(len);

                    // Track by source IP
                    connectionsByIp.computeIfAbsent(srcIp, k -> new AtomicLong())
                            .incrementAndGet();
                    bytesByIp.computeIfAbsent(srcIp, k -> new AtomicLong())
                            .addAndGet(len);

                    // Count new connections
                    if (tcp.isSyn() && !tcp.isAck()) {
                        synPackets.incrementAndGet();
                    }

                    // Print connection info
                    String direction = (dstPort == 80 || dstPort == 443) ? "→" : "←";
                    String service = (dstPort == 443 || srcPort == 443) ? "HTTPS" : "HTTP";
                    String flags = formatFlags(tcp);

                    System.out.printf("[%s] %s:%d %s %s:%d [%s] %d bytes%n",
                            service,
                            srcIp, srcPort,
                            direction,
                            ip4.dst(), dstPort,
                            flags,
                            len);
                }
            });

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String formatFlags(Tcp tcp) {
        StringBuilder sb = new StringBuilder();
        if (tcp.isSyn()) sb.append("S");
        if (tcp.isAck()) sb.append("A");
        if (tcp.isFin()) sb.append("F");
        if (tcp.isRst()) sb.append("R");
        if (tcp.isPsh()) sb.append("P");
        if (tcp.isUrg()) sb.append("U");
        return sb.length() > 0 ? sb.toString() : ".";
    }
}