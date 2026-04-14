/*
 * Copyright 2005-2026 Sly Technologies Inc.
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

/**
 * Working examples demonstrating jNetPcap SDK 3.0 features.
 *
 * <p>
 * Each example is a self-contained program covering a specific capability.
 * The examples progress from the simplest possible capture to advanced
 * multi-threaded and low-level patterns.
 * </p>
 *
 * <h2>Getting Started</h2>
 *
 * <h3>Dependency</h3>
 * <pre>{@code
 * <dependency>
 *     <groupId>com.slytechs.sdk</groupId>
 *     <artifactId>jnetpcap-sdk</artifactId>
 *     <version>3.0.0</version>
 *     <type>pom</type>
 * </dependency>
 * }</pre>
 *
 * <h3>Required JVM Arguments</h3>
 * <p>
 * jNetPcap uses the Java Foreign Function &amp; Memory (FFM) API. Add the
 * following to your JVM invocation:
 * </p>
 * <pre>
 * --enable-native-access=com.slytechs.sdk.jnetpcap,com.slytechs.sdk.common
 * </pre>
 *
 * <h3>Running an Example</h3>
 * <pre>
 * mvn compile exec:java \
 *     -Dexec.mainClass="com.slytechs.sdk.jnetpcap.examples.HelloWorld"
 * </pre>
 *
 * <h2>Examples</h2>
 *
 * <h3>Basic Capture</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.HelloWorld} —
 *     The simplest jNetPcap program. Read a pcap file, print TCP flows.</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.BasicLiveCapture} —
 *     Minimal two-stage live capture using {@code create()} and
 *     {@code activate()}.</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.LiveCaptureWithFilter} —
 *     Live capture with BPF filter, snaplen, and timeout configuration.</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.OfflineFileReading} —
 *     Read and dissect packets from a pcap or pcapng file.</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.InterfaceEnumeration} —
 *     List all available network interfaces and their addresses.</li>
 * </ul>
 *
 * <h3>Protocol Dissection</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.ProtocolDissection} —
 *     Full header access for Ethernet, IPv4, and TCP using the
 *     zero-allocation {@code hasHeader()} pattern.</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.PacketCounter} —
 *     Count packets by protocol type with percentage breakdown.</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.HttpTrafficAnalyzer} —
 *     Analyze HTTP and HTTPS traffic flows.</li>
 * </ul>
 *
 * <h3>Packet Persistence</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.SelectivePersistence} —
 *     Selectively persist packets beyond callback scope using
 *     {@code persist()} and {@code recycle()}.</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.PooledCapture} —
 *     High-volume capture with pre-allocated packet pools and zero GC
 *     pressure.</li>
 * </ul>
 *
 * <h3>Multi-threaded Processing</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.ProducerConsumer} —
 *     Single capture thread feeding multiple worker threads via a
 *     {@code BlockingQueue} with per-thread header instances.</li>
 * </ul>
 *
 * <h3>Advanced</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.PcapDumperExample} —
 *     Write filtered packets to a pcap file using {@code PcapDumper}.</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.RawPcapCapture} —
 *     Low-level {@link com.slytechs.sdk.jnetpcap.Pcap} bindings without
 *     the high-level API layer.</li>
 * </ul>
 *
 * <h2>Core Concepts</h2>
 *
 * <h3>Zero-Allocation Header Access</h3>
 * <p>
 * Pre-allocate header objects once outside the capture loop and reuse them
 * for every packet. {@code hasHeader()} binds the header to the current
 * packet's data in place — no heap allocation occurs on the hot path.
 * </p>
 * <pre>{@code
 * // Allocate once outside the loop
 * Ip4 ip4 = new Ip4();
 * Tcp tcp = new Tcp();
 *
 * pcap.loop(-1, packet -> {
 *     // hasHeader() rebinds in place — no allocation, no new instances
 *     if (packet.hasHeader(ip4) && packet.hasHeader(tcp))
 *         System.out.printf("%s:%d -> %s:%d%n",
 *             ip4.src(), tcp.srcPort(),
 *             ip4.dst(), tcp.dstPort());
 * });
 * }</pre>
 *
 * <h3>Memory Model</h3>
 * <p>
 * Every user-facing object — {@code Packet}, {@code Header}, {@code Descriptor},
 * {@code MemoryBuffer} — is a <em>view</em> over physical memory. The view
 * layer decouples the Java object from the memory it currently describes,
 * enabling zero-copy capture and safe persistence with minimal overhead.
 * </p>
 *
 * <p>Physical memory is one of two kinds:</p>
 * <ul>
 * <li><b>ScopedMemory</b> — borrowed. Bound to the native capture buffer for
 *     the duration of a single dispatch callback. Zero allocation, zero copy.
 *     Becomes invalid after the callback returns.</li>
 * <li><b>FixedMemory</b> — owned. Reference-counted off-heap memory. Valid
 *     until all views over it have been recycled (refCount reaches zero).</li>
 * </ul>
 *
 * <p>
 * Inside a dispatch callback, {@code Packet} and its {@code Descriptor} are
 * both view objects bound to {@code ScopedMemory} — the native capture buffer.
 * No Java object allocation of any kind occurs. Protocol headers ({@code Ip4},
 * {@code Tcp}, etc.) are likewise rebound in place by {@code hasHeader()}.
 * </p>
 *
 * <h3>Packet Persistence</h3>
 * <p>
 * {@code persist()} guarantees that a packet is safe to use beyond the current
 * callback scope. It performs the minimum work necessary:
 * </p>
 * <ol>
 * <li><b>Already persistent</b> (bound to {@code FixedMemory}) — increments
 *     the reference count and returns {@code this}. Zero work.</li>
 * <li><b>Not persistent, pool configured</b> — acquires a pre-allocated
 *     {@code Packet} Java instance from the instance pool and
 *     {@code FixedMemory} segments from the memory pool, copies packet data
 *     and descriptor independently, binds the view, sets refCount = 1.
 *     No heap allocation, no GC pressure.</li>
 * <li><b>Not persistent, no pool</b> — falls through to {@code copy()},
 *     allocating new {@code FixedMemory} from an auto-managed arena.</li>
 * </ol>
 *
 * <p>
 * The Java instance pool and the memory pool are independent lock-free
 * structures. A single {@code persist()} call in a pooled configuration
 * reuses both a pre-allocated Java object and pre-allocated native memory —
 * creating no garbage at all.
 * </p>
 *
 * <pre>{@code
 * pcap.loop(-1, packet -> {
 *     if (isInteresting(packet)) {
 *         // No-op if already persistent (refCount++),
 *         // pool reuse if pool configured,
 *         // heap copy as last resort
 *         Packet kept = packet.persist();
 *         queue.add(kept);
 *     }
 * });
 *
 * // Later, in any thread
 * Packet p = queue.poll();
 * process(p);
 * p.recycle();  // decrements refCount; releases to pools when zero
 * }</pre>
 *
 * <h3>Reference Counting</h3>
 * <p>
 * {@code FixedMemory} is reference-counted. Multiple views can safely share
 * the same backing memory:
 * </p>
 * <ul>
 * <li>{@code persist()} on an already-persistent packet — increments refCount,
 *     returns {@code this}</li>
 * <li>{@code duplicate()} — increments refCount, returns a new view over the
 *     same memory without copying</li>
 * <li>{@code recycle()} — decrements refCount; the Java instance and memory
 *     segments are returned to their respective pools only when refCount
 *     reaches zero</li>
 * <li>{@code recycle()} on a non-pooled object — safe no-op</li>
 * </ul>
 *
 * <h3>Configuration Separation</h3>
 * <p>
 * jNetPcap separates two distinct configuration concerns:
 * </p>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.api.NetPcap} setters —
 *     capture properties (snaplen, timeout, promisc, filter). Must be set
 *     before {@code activate()} except for {@code setFilter()} which is set
 *     after.</li>
 * <li>{@link com.slytechs.sdk.protocol.core.PacketSettings} —
 *     packet structure and memory strategy (dissection mode, zero-copy,
 *     pooled). Passed to the factory method.</li>
 * </ul>
 * <pre>{@code
 * PacketSettings settings = new PacketSettings().dissect();
 *
 * try (NetPcap pcap = NetPcap.create("eth0", settings)) {
 *     pcap.setSnaplen(65535)
 *         .setPromisc(true)
 *         .setTimeout(Duration.ofSeconds(1))
 *         .activate();
 *
 *     pcap.setFilter("tcp port 443");
 *     pcap.loop(-1, handler);
 * }
 * }</pre>
 *
 * <h3>When to Use Pools</h3>
 * <p>
 * The JDK is highly optimized for short-lived object allocation and GC.
 * For many use cases pools add no benefit:
 * </p>
 * <ul>
 * <li><b>Under ~1M pps</b> — default settings work well. JIT and GC handle
 *     allocation efficiently without pools.</li>
 * <li><b>1–10M pps</b> — consider enabling a packet pool to reduce GC
 *     pauses under sustained load.</li>
 * <li><b>10M+ pps</b> — pool configuration is essential to eliminate
 *     allocations and GC pressure from the hot path entirely.</li>
 * </ul>
 *
 * <h3>Thread Safety</h3>
 * <p>
 * {@link com.slytechs.sdk.jnetpcap.api.NetPcap} is strictly single-threaded.
 * Header instances ({@code Ip4}, {@code Tcp}, etc.) are not thread-safe —
 * each worker thread must allocate its own. Persisted
 * {@link com.slytechs.sdk.protocol.core.Packet} objects are safe to pass
 * between threads once returned from {@code persist()}.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 3.0.0
 * @see com.slytechs.sdk.jnetpcap.api.NetPcap
 * @see com.slytechs.sdk.protocol.core.PacketSettings
 * @see com.slytechs.sdk.jnetpcap.Pcap
 */
package com.slytechs.sdk.jnetpcap.examples;