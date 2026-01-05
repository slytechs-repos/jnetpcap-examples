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
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;
import com.slytechs.sdk.protocol.tcpip.udp.Udp;

/**
 * Example 5: Protocol Dissection
 * 
 * Demonstrates the zero-allocation hasHeader() pattern for accessing
 * protocol headers. Headers are pre-allocated once and rebound to each
 * packet's data - no allocation during the hot path.
 * 
 * Shows how to:
 * - Enable dissection with PacketSettings
 * - Access Ethernet, IPv4, TCP, and UDP headers
 * - Read header fields (addresses, ports, flags, etc.)
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class ProtocolDissection {

    private static final String DEFAULT_FILE = "pcaps/HTTP.cap";

    public static void main(String[] args) throws PcapException {
        String filename = args.length > 0 ? args[0] : DEFAULT_FILE;
        new ProtocolDissection().run(filename);
    }

    public void run(String filename) throws PcapException {
    	
    	NetPcap.activateLicense();
    	
        System.out.printf("Dissecting packets from: %s%n", filename);
        System.out.println();

        // Enable protocol dissection
        PacketSettings settings = new PacketSettings()
                .dissect();

        // Pre-allocate header instances (reused for every packet)
        Ethernet eth = new Ethernet();
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();

        try (NetPcap pcap = NetPcap.openOffline(filename, settings)) {

            final int[] count = {0};

            pcap.loop(10, packet -> {  // First 10 packets only
                count[0]++;
                System.out.printf("=== Packet #%d ===%n", count[0]);
                System.out.printf("Timestamp: %s%n", packet.timestampInfo());
                System.out.printf("Captured: %d bytes, Wire: %d bytes%n",
                        packet.captureLength(), packet.wireLength());

                // Layer 2 - Ethernet
                if (packet.hasHeader(eth)) {
                    System.out.println();
                    System.out.println("Ethernet:");
                    System.out.printf("  Source:      %s%n", eth.src());
                    System.out.printf("  Destination: %s%n", eth.dst());
                    System.out.printf("  Type:        0x%04X%n", eth.etherType());
                }

                // Layer 3 - IPv4
                if (packet.hasHeader(ip4)) {
                    System.out.println();
                    System.out.println("IPv4:");
                    System.out.printf("  Source:      %s%n", ip4.src());
                    System.out.printf("  Destination: %s%n", ip4.dst());
                    System.out.printf("  Version:     %d%n", ip4.version());
                    System.out.printf("  IHL:         %d (%d bytes)%n", ip4.ihl(), ip4.ihl() * 4);
                    System.out.printf("  Total Len:   %d%n", ip4.totalLength());
                    System.out.printf("  TTL:         %d%n", ip4.ttl());
                    System.out.printf("  Protocol:    %d%n", ip4.protocol());
                    System.out.printf("  Checksum:    0x%04X%n", ip4.checksum());
                    System.out.printf("  Flags:       DF=%b MF=%b%n", ip4.isDf(), ip4.isMf());
                    System.out.printf("  Frag Offset: %d%n", ip4.fragOffset());
                }

                // Layer 4 - TCP
                if (packet.hasHeader(tcp)) {
                    System.out.println();
                    System.out.println("TCP:");
                    System.out.printf("  Source Port: %d%n", tcp.srcPort());
                    System.out.printf("  Dest Port:   %d%n", tcp.dstPort());
                    System.out.printf("  Seq:         %d%n", tcp.seq());
                    System.out.printf("  Ack:         %d%n", tcp.ack());
                    System.out.printf("  Header Len:  %d (%d bytes)%n", tcp.hlen(), tcp.hlenBytes());
                    System.out.printf("  Window:      %d%n", tcp.window());
                    System.out.printf("  Checksum:    0x%04X%n", tcp.checksum());
                    System.out.printf("  Flags:       SYN=%b ACK=%b FIN=%b RST=%b PSH=%b URG=%b%n",
                            tcp.isSyn(), tcp.isAck(), tcp.isFin(),
                            tcp.isRst(), tcp.isPsh(), tcp.isUrg());
                }

                // Layer 4 - UDP
                if (packet.hasHeader(udp)) {
                    System.out.println();
                    System.out.println("UDP:");
                    System.out.printf("  Source Port: %d%n", udp.srcPort());
                    System.out.printf("  Dest Port:   %d%n", udp.dstPort());
                    System.out.printf("  Length:      %d%n", udp.length());
                    System.out.printf("  Checksum:    0x%04X%n", udp.checksum());
                }

                System.out.println();
            });

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}