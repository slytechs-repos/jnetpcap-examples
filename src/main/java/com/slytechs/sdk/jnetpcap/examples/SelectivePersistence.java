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

import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

/**
 * Example 10: Selective Persistence
 * 
 * Demonstrates the packet persistence API for keeping packets beyond
 * the callback scope. Packets in callbacks are bound to native buffers
 * and are only valid within the callback. To queue packets for later
 * processing, use persist().
 * 
 * persist() behavior:
 * - If packet is already persistent (FixedMemory): returns same instance
 * - If packet is scoped (ScopedMemory): copies to new FixedMemory, returns copy
 * 
 * After processing, call recycle() to return pooled packets (no-op for non-pooled).
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class SelectivePersistence {

    private static final String DEFAULT_FILE = "pcaps/HTTP.cap";

    public static void main(String[] args) throws PcapException {
        String filename = args.length > 0 ? args[0] : DEFAULT_FILE;
        new SelectivePersistence().run(filename);
    }

    public void run(String filename) throws PcapException {
        NetPcap.activateLicense();

        System.out.printf("Selective persistence from: %s%n", filename);
        System.out.println("Keeping only TCP SYN packets...");
        System.out.println();

        // Enable dissection
        PacketSettings settings = new PacketSettings()
                .dissect();

        // Pre-allocate headers
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();

        // Queue for persisted packets
        Queue<Packet> synPackets = new ConcurrentLinkedQueue<>();
        AtomicInteger totalCount = new AtomicInteger();
        AtomicInteger persistedCount = new AtomicInteger();

        try (NetPcap pcap = NetPcap.openOffline(filename, settings)) {

            pcap.loop(-1, packet -> {
                totalCount.incrementAndGet();

                // Check if this is a TCP SYN packet (new connection)
                if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
                    if (tcp.isSyn() && !tcp.isAck()) {
                        // This is a SYN packet - persist it!
                        Packet keeper = packet.persist();
                        synPackets.add(keeper);
                        persistedCount.incrementAndGet();

                        System.out.printf("Persisted SYN: %s:%d → %s:%d%n",
                                ip4.src(), tcp.srcPort(),
                                ip4.dst(), tcp.dstPort());
                    }
                }
                // Non-SYN packets are not persisted - their memory is
                // released when callback returns
            });

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        System.out.println();
        System.out.printf("Processed %d packets, persisted %d SYN packets%n",
                totalCount.get(), persistedCount.get());
        System.out.println();

        // Now process the queued packets (outside callback scope)
        System.out.println("=== Processing Persisted Packets ===");

        // Need fresh headers for this context
        Ip4 ip4Post = new Ip4();
        Tcp tcpPost = new Tcp();

        int processed = 0;
        Packet packet;
        while ((packet = synPackets.poll()) != null) {
            processed++;

            if (packet.hasHeader(ip4Post) && packet.hasHeader(tcpPost)) {
                System.out.printf("#%d: SYN from %s:%d → %s:%d (seq=%d)%n",
                        processed,
                        ip4Post.src(), tcpPost.srcPort(),
                        ip4Post.dst(), tcpPost.dstPort(),
                        tcpPost.seq());
            }

            // Done with this packet - recycle it
            // (no-op if non-pooled, returns to pool if pooled)
            packet.recycle();
        }

        System.out.println();
        System.out.printf("Processed %d persisted packets%n", processed);
    }
}