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
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.PacketSettings;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

/**
 * Example 14: Producer-Consumer Pattern
 * 
 * Demonstrates multi-threaded packet processing with:
 * - Single capture thread (NetPcap is not thread-safe)
 * - Multiple worker threads for packet processing
 * - BlockingQueue for thread-safe packet transfer
 * - persist() to keep packets beyond callback scope
 * 
 * Thread safety rules:
 * - NetPcap: Single-threaded only
 * - Header instances: Not thread-safe, use per-thread instances
 * - Persisted packets: Safe to pass between threads
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class ProducerConsumer {

    private static final int WORKER_THREADS = 4;
    private static final int QUEUE_CAPACITY = 10000;

    public static void main(String[] args) throws Exception {
        new ProducerConsumer().run();
    }

    public void run() throws Exception {
        String device = NetPcap.findAllDevs()
                .stream()
                .filter(d -> d.isUp() && !d.isLoopback())
                .findFirst()
                .map(d -> d.name())
                .orElseThrow(() -> new IllegalStateException("No suitable network interface found"));

        System.out.printf("Producer-Consumer capture on: %s%n", device);
        System.out.printf("Workers: %d, Queue capacity: %d%n", WORKER_THREADS, QUEUE_CAPACITY);
        System.out.println("Press Ctrl+C to stop...");
        System.out.println();

        // Shared state
        BlockingQueue<Packet> workQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
        AtomicBoolean running = new AtomicBoolean(true);
        AtomicLong capturedCount = new AtomicLong();
        AtomicLong processedCount = new AtomicLong();
        AtomicLong droppedCount = new AtomicLong();

        // Shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            running.set(false);
            System.out.println();
            System.out.println("=== Final Statistics ===");
            System.out.printf("Captured: %,d%n", capturedCount.get());
            System.out.printf("Processed: %,d%n", processedCount.get());
            System.out.printf("Dropped (queue full): %,d%n", droppedCount.get());
        }));

        // Start worker threads
        ExecutorService workers = Executors.newFixedThreadPool(WORKER_THREADS);
        for (int i = 0; i < WORKER_THREADS; i++) {
            final int workerId = i;
            workers.submit(() -> workerThread(workerId, workQueue, running, processedCount));
        }

        // Capture thread (main thread)
        PacketSettings settings = new PacketSettings()
                .dissect();

        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();

        try (NetPcap pcap = NetPcap.create(device, settings)) {

            pcap.setSnaplen(256)
                .setPromisc(true)
                .setTimeout(Duration.ofMillis(100))
                .activate();

            pcap.setFilter("tcp");

            while (running.get()) {
                pcap.dispatch(100, packet -> {
                    capturedCount.incrementAndGet();

                    // Only persist interesting packets
                    if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
                        // Persist for worker thread processing
                        Packet persisted = packet.persist();

                        // Non-blocking offer to queue
                        if (!workQueue.offer(persisted)) {
                            // Queue full - recycle and count as dropped
                            persisted.recycle();
                            droppedCount.incrementAndGet();
                        }
                    }
                });
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        // Shutdown workers
        running.set(false);
        workers.shutdown();
        workers.awaitTermination(5, TimeUnit.SECONDS);

        // Drain remaining queue
        Packet remaining;
        while ((remaining = workQueue.poll()) != null) {
            remaining.recycle();
        }
    }

    /**
     * Worker thread - processes packets from the queue.
     * Each worker has its own header instances (not thread-safe).
     */
    private void workerThread(int id, BlockingQueue<Packet> queue,
                              AtomicBoolean running, AtomicLong processedCount) {
        
        // Thread-local headers (each thread needs its own)
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();

        System.out.printf("Worker %d started%n", id);

        try {
            while (running.get() || !queue.isEmpty()) {
                // Poll with timeout to check running flag periodically
                Packet packet = queue.poll(100, TimeUnit.MILLISECONDS);

                if (packet != null) {
                    try {
                        // Process the packet
                        if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
                            // Simulate processing...
                            processPacket(id, ip4, tcp);
                            processedCount.incrementAndGet();
                        }
                    } finally {
                        // Always recycle when done
                        packet.recycle();
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        System.out.printf("Worker %d stopped%n", id);
    }

    /**
     * Simulate packet processing.
     */
    private void processPacket(int workerId, Ip4 ip4, Tcp tcp) {
        // Example: Log SYN packets
        if (tcp.isSyn() && !tcp.isAck()) {
            System.out.printf("[W%d] SYN: %s:%d → %s:%d%n",
                    workerId,
                    ip4.src(), tcp.srcPort(),
                    ip4.dst(), tcp.dstPort());
        }
    }
}