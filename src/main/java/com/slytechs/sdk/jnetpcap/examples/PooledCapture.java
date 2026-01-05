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
import com.slytechs.sdk.common.memory.pool.Pool;
import com.slytechs.sdk.common.memory.pool.PoolSettings;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.core.stack.PacketPool;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

/**
 * Example 11: Pooled Capture
 * 
 * Demonstrates high-volume packet persistence using explicit packet pools.
 * For high-rate capture where many packets need to be persisted, using
 * pools avoids allocation overhead and provides predictable memory usage.
 * 
 * <h2>Pool Types</h2>
 * <ul>
 * <li>{@code PacketPool.ofFixedSize(size)} - Single uniform packet size</li>
 * <li>{@code PacketPool.ofDefaultBuckets()} - Network-optimized bucket sizes</li>
 * <li>{@code PacketPool.ofBucketed(sizes...)} - Custom bucket sizes</li>
 * </ul>
 * 
 * <h2>persistTo(pool) vs persist()</h2>
 * <ul>
 * <li>{@code persist()} - Auto-allocates memory, may trigger GC under load</li>
 * <li>{@code persistTo(pool)} - Uses pre-allocated pool memory, predictable performance</li>
 * </ul>
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class PooledCapture {

    private static final String DEFAULT_FILE = "pcaps/HTTP.cap";

    public static void main(String[] args) throws PcapException {
        String filename = args.length > 0 ? args[0] : DEFAULT_FILE;
        new PooledCapture().run(filename);
    }

    public void run(String filename) throws PcapException {
        NetPcap.activateLicense();

        System.out.printf("Pooled capture from: %s%n", filename);
        System.out.println();

        // Configure packet pool for persistence
        // - capacity: Total number of packets in pool
        // - preallocate: Allocate all memory upfront for predictable performance
        PoolSettings poolSettings = new PoolSettings()
                .capacity(100)
                .preallocate(true);

        // Create fixed-size pool - all packets use same memory size (9KB for jumbo frames)
        Pool<Packet> persistPool = PacketPool.ofFixedSize(poolSettings, 9000);

        System.out.printf("Pool created: capacity=%d, segmentSize=9000%n", poolSettings.maxCapacity());
        System.out.printf("Pool available: %d%n", persistPool.available());
        System.out.println();

        // Enable dissection
        PacketSettings settings = new PacketSettings()
                .dissect();

        // Pre-allocate headers
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();

        // Queue for persisted packets
        Queue<Packet> packetQueue = new ConcurrentLinkedQueue<>();
        AtomicInteger totalCount = new AtomicInteger();
        AtomicInteger persistedCount = new AtomicInteger();
        AtomicInteger poolExhaustedCount = new AtomicInteger();

        try (NetPcap pcap = NetPcap.openOffline(filename, settings)) {

            pcap.loop(-1, packet -> {
                totalCount.incrementAndGet();

                // Persist TCP packets to the pool
                if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {

                    // Check pool availability before persisting
                    if (persistPool.available() > 0) {
                        // Persist using pool - no allocation, predictable performance
                        Packet pooled = packet.persistTo(persistPool);
                        packetQueue.add(pooled);
                        persistedCount.incrementAndGet();
                    } else {
                        // Pool exhausted - could wait, drop, or use fallback
                        poolExhaustedCount.incrementAndGet();
                    }
                }
            });

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        System.out.printf("Capture complete: %d total, %d persisted, %d dropped (pool full)%n",
                totalCount.get(), persistedCount.get(), poolExhaustedCount.get());
        System.out.printf("Pool available after capture: %d%n", persistPool.available());
        System.out.println();

        // Process queued packets
        System.out.println("=== Processing Queued Packets ===");

        Ip4 ip4Post = new Ip4();
        Tcp tcpPost = new Tcp();

        int processed = 0;
        Packet packet;
        while ((packet = packetQueue.poll()) != null) {
            processed++;

            if (packet.hasHeader(ip4Post) && packet.hasHeader(tcpPost)) {
                // Process packet...
                if (processed <= 5 || processed % 100 == 0) {
                    System.out.printf("#%d: %s:%d → %s:%d%n",
                            processed,
                            ip4Post.src(), tcpPost.srcPort(),
                            ip4Post.dst(), tcpPost.dstPort());
                }
            }

            // Return packet to pool for reuse
            packet.recycle();
        }

        System.out.println();
        System.out.printf("Processed %d packets%n", processed);
        System.out.printf("Pool available after processing: %d%n", persistPool.available());

        // Clean up pool
        persistPool.close();
    }
}
