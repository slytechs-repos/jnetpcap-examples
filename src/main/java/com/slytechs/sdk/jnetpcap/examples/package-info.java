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

/**
 * Example programs demonstrating usage of the jNetPcap SDK.
 *
 * <p>
 * These standalone examples illustrate core features of jNetPcap v3, including:
 * </p>
 * <ul>
 * <li>Live and offline packet capture using the modern
 * {@code create() → activate()} pattern</li>
 * <li>Zero-allocation protocol header access via {@code hasHeader()}</li>
 * <li>Protocol dissection with {@link com.slytechs.sdk.protocol.core.PacketSettings}</li>
 * <li>Packet persistence with {@code persist()}, {@code copy()}, and pooling</li>
 * <li>Configuration of capture parameters (snaplen, filters, timeouts)</li>
 * <li>Multi-threaded processing patterns</li>
 * <li>Safe resource management with try-with-resources</li>
 * </ul>
 *
 * <h2>Running the Examples</h2>
 *
 * <h3>JVM Arguments</h3>
 * <p>
 * jNetPcap uses the Java Foreign Function &amp; Memory (FFM) API to access native
 * libpcap. The following JVM arguments are required:
 * </p>
 * <pre>
 * --enable-native-access=com.slytechs.sdk.jnetpcap,com.slytechs.sdk.common
 * </pre>
 *
 * <h3>License Activation</h3>
 * <p>
 * The jNetPcap SDK comes with a pre-installed unlimited community license. Before 
 * using any jNetPcap functionality, you must activate the license by calling
 * {@link com.slytechs.jnet.jnetpcap.api.NetPcap#activateLicense()}. This should be
 * done once at application startup, before any capture operations. Internet 
 * connectivity is required for license activation.
 * </p>
 * <pre>{@code
 * public static void main(String[] args) throws PcapException {
 *     // Activate license first - required before any jNetPcap operations
 *     NetPcap.activateLicense();
 *     
 *     // Now proceed with capture...
 *     try (NetPcap pcap = NetPcap.create("eth0")) {
 *         pcap.activate();
 *         pcap.loop(-1, packet -> {
 *             // Process packets...
 *         });
 *     }
 * }
 * }</pre>
 *
 * <h3>Complete Example Launch</h3>
 * <pre>
 * java --enable-native-access=com.slytechs.sdk.jnetpcap,com.slytechs.sdk.common \
 *      -cp jnetpcap-sdk-3.0.0.jar:your-app.jar \
 *      com.slytechs.sdk.jnetpcap.examples.BasicLiveCapture
 * </pre>
 *
 * <h2>Example Categories</h2>
 *
 * <h3>Basic Capture</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.BasicLiveCapture} - Minimal two-stage capture</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.LiveCaptureWithFilter} - BPF filters and configuration</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.OfflineFileReading} - Read pcap/pcapng files</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.InterfaceEnumeration} - List network devices</li>
 * </ul>
 *
 * <h3>Protocol Dissection</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.ProtocolDissection} - Full header access demonstration</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.PacketCounter} - Count packets by protocol</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.HttpTrafficAnalyzer} - Analyze HTTP/HTTPS traffic</li>
 * </ul>
 *
 * <h3>Packet Persistence</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.SelectivePersistence} - Queue packets with persist()</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.PooledCapture} - High-volume pooled persistence</li>
 * </ul>
 *
 * <h3>Multi-threaded Processing</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.ProducerConsumer} - Capture + worker threads</li>
 * </ul>
 *
 * <h3>Advanced</h3>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.PcapDumperExample} - Write packets to file</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.examples.RawPcapCapture} - Low-level Pcap bindings</li>
 * </ul>
 *
 * <h2>Configuration Separation</h2>
 * <p>
 * jNetPcap separates two configuration concerns:
 * </p>
 * <ul>
 * <li><b>NetPcap setters</b> - Capture properties (snaplen, timeout, filter, promisc)</li>
 * <li><b>PacketSettings</b> - Packet structure (dissection mode, memory strategy)</li>
 * </ul>
 *
 * <pre>{@code
 * // PacketSettings - how packets are structured
 * PacketSettings settings = new PacketSettings()
 *     .dissect();  // Enable protocol dissection
 *
 * try (NetPcap pcap = NetPcap.create("eth0", settings)) {
 *     // NetPcap setters - capture properties
 *     pcap.setSnaplen(65535)
 *         .setTimeout(Duration.ofSeconds(1))
 *         .setPromisc(true)
 *         .activate();
 *
 *     pcap.setFilter("tcp port 80");
 *     pcap.loop(-1, handler);
 * }
 * }</pre>
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 * @see com.slytechs.jnet.jnetpcap.api.NetPcap
 * @see com.slytechs.sdk.protocol.core.PacketSettings
 * @see com.slytechs.sdk.jnetpcap.Pcap
 * @since 3.0.0
 */
package com.slytechs.sdk.jnetpcap.examples;