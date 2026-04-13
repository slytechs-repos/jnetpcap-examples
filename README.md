> # jNetPcap SDK Examples
>
> Examples demonstrating jNetPcap SDK usage for packet capture and protocol analysis.
>
> ## Quick Start
>
> ### Maven Dependency
>
> ```xml
> <dependency>
>        <groupId>com.slytechs.sdk</groupId>
>        <artifactId>jnetpcap-sdk</artifactId>
>        <version>3.0.0</version>
>        <type>pom</type>
> </dependency>
> ```
>
> ### JVM Arguments
>
> jNetPcap uses the Java Foreign Function & Memory (FFM) API. The following JVM arguments are required:
>
> ```bash
> --enable-native-access=com.slytechs.sdk.jnetpcap,com.slytechs.sdk.common
> ```
>
> ### License Activation
>
> The jNetPcap SDK includes a pre-installed Community Edition license that activates automatically on first use. No setup or internet connectivity required at startup.
>
> ### Running Examples
> 
>    ```bash
>     # Clone the repository
>    git clone https://github.com/slytechs-repos/jnetpcap-examples.git
> cd jnetpcap-examples
> 
># Run a specific example
> mvn compile exec:java -Dexec.mainClass="com.slytechs.sdk.jnetpcap.examples.ProtocolDissection"
>```
> 
> ### Requirements
> 
> - Java 22+
> - Native libpcap library (Linux/macOS) or Npcap/WinPcap (Windows)
> 
> ------
> 
>## Examples Overview
> 
>### Basic Capture
> 
> **BasicLiveCapture** - Simplest possible live capture
>
> ```java
>try (NetPcap pcap = NetPcap.create(device)) {
>     pcap.activate();
>
>     pcap.loop(-1, packet -> {
>        System.out.printf("[%s] wire=%d cap=%d%n",
>                 packet.timestampInfo(),
>                 packet.wireLength(),
>                 packet.captureLength());
>     });
> }
> ```
> 
> **LiveCaptureWithFilter** - Live capture with BPF filtering
> 
> ```java
> try (NetPcap pcap = NetPcap.create(device)) {
>     pcap.setSnaplen(128)
>         .setPromisc(true)
>         .setTimeout(Duration.ofMillis(100))
>         .activate();
> 
>     pcap.setFilter("tcp port 80 or tcp port 443");
> 
>     pcap.dispatch(100, packet -> {
>        System.out.printf("[%s] %d bytes%n",
>                 packet.timestampInfo(),
>                packet.captureLength());
>     });
> }
> ```
> 
> **OfflineFileReading** - Read pcap/pcapng files
> 
> ```java
> try (NetPcap pcap = NetPcap.openOffline("pcaps/HTTP.cap")) {
>     pcap.loop(-1, packet -> {
>        System.out.printf("Captured: %d bytes%n", packet.captureLength());
>     });
>}
> ```
> 
> **InterfaceEnumeration** - List available network devices
> 
> ```java
> List<PcapIf> devices = NetPcap.findAllDevs();
> for (PcapIf dev : devices) {
>     System.out.printf("%s - %s%n", dev.name(), dev.description().orElse(""));
>}
> ```
>
> ------
>
> ### Protocol Dissection
> 
> **ProtocolDissection** - Full header access with zero-allocation pattern
> 
> ```java
> PacketSettings settings = new PacketSettings().dissect();
> 
> // Pre-allocate headers once — reused for every packet, zero GC pressure
> Ethernet eth = new Ethernet();
> Ip4 ip4 = new Ip4();
> Tcp tcp = new Tcp();
> 
> try (NetPcap pcap = NetPcap.openOffline("pcaps/HTTP.cap", settings)) {
>     pcap.loop(10, packet -> {
>         if (packet.hasHeader(eth))
>             System.out.printf("Ethernet: %s -> %s%n", eth.src(), eth.dst());
> 
>         if (packet.hasHeader(ip4))
>             System.out.printf("IPv4: %s -> %s%n", ip4.src(), ip4.dst());
> 
>         if (packet.hasHeader(tcp))
>             System.out.printf("TCP: %d -> %d [%s]%n",
>                     tcp.srcPort(), tcp.dstPort(),
>                     tcp.isSyn() ? "SYN" : "");
>     });
> }
> ```
> 
>**PacketCounter** - Count packets by protocol type
> 
>```java
> PacketSettings settings = new PacketSettings().dissect();
> Ip4 ip4 = new Ip4();
> Tcp tcp = new Tcp();
> Udp udp = new Udp();
> 
> Map<String, Long> stats = new HashMap<>();
> 
> try (NetPcap pcap = NetPcap.openOffline(filename, settings)) {
>     pcap.loop(-1, (counters, packet) -> {
>         if (packet.hasHeader(ip4)) counters.merge("ipv4", 1L, Long::sum);
>         if (packet.hasHeader(tcp)) counters.merge("tcp", 1L, Long::sum);
>         if (packet.hasHeader(udp)) counters.merge("udp", 1L, Long::sum);
>     }, stats);
> }
> ```
> 
> **HttpTrafficAnalyzer** - Analyze HTTP/HTTPS traffic with flow tracking
> 
>------
> 
>### Packet Persistence
> 
>**SelectivePersistence** - Keep packets beyond callback scope
> 
> ```java
> Queue<Packet> synPackets = new ConcurrentLinkedQueue<>();
> 
> pcap.loop(-1, packet -> {
>     if (packet.hasHeader(tcp) && tcp.isSyn() && !tcp.isAck()) {
>         synPackets.add(packet.persist());
>     }
> });
> 
> // Process persisted packets outside callback
> Packet p;
> while ((p = synPackets.poll()) != null) {
>     // Process...
>     p.recycle();
> }
> ```
> 
>**PooledCapture** - High-volume persistence with packet pools
> 
>```java
> Pool<Packet> pool = PacketPool.ofFixed(
>     new PoolSettings().capacity(1000).segmentSize(9000).preallocate(true));
> 
> pcap.loop(-1, packet -> {
>     if (pool.available() > 0)
>         workQueue.add(packet.persistTo(pool));
> });
> ```
> 
> ------
> 
> ### Multi-threaded Processing
> 
> **ProducerConsumer** - Single capture thread feeding multiple worker threads
> 
>```java
> BlockingQueue<Packet> workQueue = new LinkedBlockingQueue<>(10000);
>
> // Capture thread — NetPcap is single-threaded
>pcap.dispatch(100, packet -> {
>     if (packet.hasHeader(tcp))
>         workQueue.offer(packet.persist());
> });
> 
> // Worker threads — each needs its own header instances
> Ip4 ip4 = new Ip4();   // thread-local
> Tcp tcp = new Tcp();    // thread-local
> 
> while (running) {
>     Packet p = workQueue.poll(100, TimeUnit.MILLISECONDS);
>     if (p != null) {
>         if (p.hasHeader(ip4) && p.hasHeader(tcp)) { /* process */ }
>         p.recycle();
>     }
> }
>     ```
> 
> ------
> 
> ### Advanced
> 
> **PcapDumperExample** - Write captured packets to a pcap file
> 
> ```java
> MemorySegment hdrSegment = Arena.ofAuto().allocate(24);
> PcapHeaderABI abi = PcapHeaderABI.PADDED_LE;
> 
>try (PcapDumper dumper = pcap.dumpOpen("output.pcap")) {
>     pcap.dispatch(100, packet -> {
>        var desc = packet.descriptor();
>         long ts = desc.timestamp();
>        var tsu = desc.timestampUnit();
> 
>         abi.tvSec(hdrSegment, tsu.toEpochSecond(ts));
>         abi.tvUsec(hdrSegment, tsu.toMicroAdjustment(ts));
>             abi.captureLength(hdrSegment, packet.captureLength());
>         abi.wireLength(hdrSegment, packet.wireLength());
> 
>         dumper.dump(hdrSegment, packet.boundMemory().segment());
>     });
>     dumper.flush();
> }
> ```
> 
> Note: `dump(Packet)` direct support is planned for 3.1.0.
> 
>**RawPcapCapture** - Low-level Pcap bindings without dissection
> 
>```java
> try (Pcap pcap = Pcap.create(device)) {
>     pcap.activate();
> 
>     PcapHeaderABI abi = pcap.getPcapHeaderABI();
> 
>         pcap.loop(100, (String user, MemorySegment header, MemorySegment data) -> {
>         int capLen = abi.captureLength(header);
>             long tsSec = abi.tvSec(header);
>     }, "");
> }
> ```
> 
> ------
> 
> ## Key Concepts
>
> ### Configuration Separation
>
> jNetPcap separates two configuration concerns:
>
> | Configuration   | Purpose            | Examples                          |
>| --------------- | ------------------ | --------------------------------- |
> | NetPcap setters | Capture properties | snaplen, timeout, filter, promisc |
> | PacketSettings  | Packet structure   | dissection mode, memory strategy  |
> 
> ### Header Reuse Pattern
>
> Allocate headers once outside the loop — `hasHeader()` binds them to each packet's data in place:
> 
> ```java
> final Ip4 ip4 = new Ip4();
> final Tcp tcp = new Tcp();
> 
> pcap.dispatch(-1, packet -> {
>     if (packet.hasHeader(ip4))
>         System.out.println(ip4.src());
> });
> ```
> 
> ### Packet Persistence
> 
> | Method            | Use Case                   | Memory               |
>| ----------------- | -------------------------- | -------------------- |
> | `persist()`       | Queue for later processing | Copies to new buffer |
>| `persistTo(pool)` | High-volume capture        | Uses pool memory     |
> | `copy()`          | Independent lifecycle      | Full deep copy       |
>| `recycle()`       | Return pooled packet       | Returns to pool      |
> 
> ### Thread Safety
> 
> | Component         | Thread Safety                              |
> | ----------------- | ------------------------------------------ |
> | NetPcap / Pcap    | Not thread-safe — one thread per handle    |
> | Header instances  | Not thread-safe — use per-thread instances |
> | Persisted packets | Safe to pass between threads               |
> | PacketSettings    | Thread-safe after construction             |
> 
> ------
> 
>## What's Included
> 
>The `jnetpcap-sdk` dependency provides:
> 
>| Module             | Description                                 |
> | ------------------ | ------------------------------------------- |
> | jnetpcap-api       | High-level NetPcap API                      |
> | jnetpcap-bindings  | libpcap FFM bindings                        |
> | sdk-protocol-core  | Packet, Header, PacketSettings, descriptors |
> | sdk-protocol-tcpip | Ethernet, IPv4/6, TCP, UDP, ICMP            |
> | sdk-common         | Memory management and utilities             |
>
> ### Optional Protocol Packs
>
> ```xml
> <!-- HTTP, TLS, QUIC, HTTP/2, HTTP/3 -->
> <dependency>
>    <groupId>com.slytechs.sdk</groupId>
>     <artifactId>sdk-protocol-web</artifactId>
>    <version>3.0.0</version>
> </dependency>
>```
> 
> ------
> 
> ## Sample Pcap Files
> 
> The `pcaps/` directory includes sample captures:
>
> | File                              | Description            |
>| --------------------------------- | ---------------------- |
> | HTTP.cap                          | HTTP traffic           |
>| varied-traffic-capture-lan.pcapng | Mixed LAN traffic      |
> | IPv4-ipf.pcapng                   | IPv4 fragmentation     |
> | ipv6-udp-fragmented.pcap          | IPv6 UDP fragmentation |
> | 6to4.pcap                         | IPv6 tunneling         |
> | sr-header.pcap                    | Segment routing        |
> 
> ------
> 
> ## Resources
> 
> - [jNetPcap SDK](https://github.com/slytechs-repos/jnetpcap-sdk) - Main SDK repository
> - [Javadocs](https://slytechs-repos.github.io/jnetpcap-api/) - API reference
> - [Sly Technologies](https://www.slytechs.com/) - Company website
> 
> ------
> 
>## License
> 
>Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
