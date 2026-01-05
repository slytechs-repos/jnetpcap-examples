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
>     <groupId>com.slytechs.sdk</groupId>
>     <artifactId>jnetpcap-sdk</artifactId>
>     <version>3.0.0</version>
>     <type>pom</type>
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
> The jNetPcap SDK comes with a pre-installed unlimited community license. Call `activateLicense()` once at application startup before any capture operations. Internet connectivity is required for activation.
>
> ```java
> public static void main(String[] args) throws PcapException {
>     NetPcap.activateLicense();  // Required - activates community license
>     
>     // Now proceed with capture...
> }
> ```
>
> ### Running Examples
>
> ```bash
> # Clone the repository
> git clone https://github.com/slytechs-repos/jnetpcap-examples.git
> cd jnetpcap-examples
> 
> # Run a specific example
> mvn compile exec:java -Dexec.mainClass="com.slytechs.sdk.jnetpcap.examples.ProtocolDissection"
> ```
>
> ### Requirements
>
> - Java 22+
> - Native libpcap library (Linux/macOS) or Npcap/WinPcap (Windows)
>
> ## Examples Overview
>
> ### Basic Capture
>
> **LiveCaptureWithFilter** - Live capture with BPF filtering and configuration
>
> ```java
> NetPcap.activateLicense();
> 
> try (NetPcap pcap = NetPcap.create(device)) {
>     pcap.setSnaplen(128)
>         .setPromisc(true)
>         .setTimeout(Duration.ofMillis(100))
>         .setImmediateMode(true)
>         .activate();
> 
>     pcap.setFilter("tcp port 80 or tcp port 443");
> 
>     pcap.dispatch(100, packet -> {
>         System.out.printf("[%s] %d bytes%n",
>                 packet.timestampInfo(),
>                 packet.captureLength());
>     });
> }
> ```
>
> **OfflineFileReading** - Read pcap/pcapng files
>
> ```java
> NetPcap.activateLicense();
> 
> try (NetPcap pcap = NetPcap.openOffline("pcaps/HTTP.cap")) {
>     pcap.loop(-1, packet -> {
>         System.out.printf("Captured: %d bytes%n", packet.captureLength());
>     });
> }
> ```
>
> **InterfaceEnumeration** - List available network devices
>
> ```java
> NetPcap.activateLicense();
> 
> List<PcapIf> devices = NetPcap.findAllDevs();
> for (PcapIf dev : devices) {
>     System.out.printf("%s - %s%n", dev.name(), dev.description().orElse(""));
> }
> ```
>
> ### Protocol Dissection
>
> **ProtocolDissection** - Full header access with zero-allocation pattern
>
> ```java
> NetPcap.activateLicense();
> 
> PacketSettings settings = new PacketSettings().dissect();
> 
> // Pre-allocate headers (reused for every packet - zero allocation)
> Ethernet eth = new Ethernet();
> Ip4 ip4 = new Ip4();
> Tcp tcp = new Tcp();
> 
> try (NetPcap pcap = NetPcap.openOffline("pcaps/HTTP.cap", settings)) {
>     pcap.loop(10, packet -> {
>         if (packet.hasHeader(eth)) {
>             System.out.printf("Ethernet: %s → %s%n", eth.src(), eth.dst());
>         }
> 
>         if (packet.hasHeader(ip4)) {
>             System.out.printf("IPv4: %s → %s%n", ip4.src(), ip4.dst());
>         }
> 
>         if (packet.hasHeader(tcp)) {
>             System.out.printf("TCP: %d → %d [%s]%n",
>                     tcp.srcPort(), tcp.dstPort(),
>                     tcp.isSyn() ? "SYN" : "");
>         }
>     });
> }
> ```
>
> **PacketCounter** - Count packets by protocol type
>
> ```java
> NetPcap.activateLicense();
> 
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
> ### Packet Persistence
>
> **SelectivePersistence** - Keep packets beyond callback scope
>
> ```java
> Queue<Packet> synPackets = new ConcurrentLinkedQueue<>();
> 
> pcap.loop(-1, packet -> {
>     if (packet.hasHeader(tcp) && tcp.isSyn() && !tcp.isAck()) {
>         // Persist packet for later processing
>         Packet keeper = packet.persist();
>         synPackets.add(keeper);
>     }
> });
> 
> // Process persisted packets outside callback
> Packet packet;
> while ((packet = synPackets.poll()) != null) {
>     // Process...
>     packet.recycle();  // Return to pool when done
> }
> ```
>
> **PooledCapture** - High-volume persistence with packet pools
>
> ```java
> PoolSettings poolSettings = new PoolSettings()
>         .capacity(1000)
>         .segmentSize(9000)
>         .preallocate(true);
> 
> Pool<Packet> persistPool = PacketPool.ofFixed(poolSettings);
> 
> pcap.loop(-1, packet -> {
>     if (persistPool.available() > 0) {
>         Packet pooled = packet.persistTo(persistPool);
>         workQueue.add(pooled);
>     }
> });
> ```
>
> ### Multi-threaded Processing
>
> **ProducerConsumer** - Capture thread with worker threads
>
> ```java
> BlockingQueue<Packet> workQueue = new LinkedBlockingQueue<>(10000);
> 
> // Capture thread
> pcap.dispatch(100, packet -> {
>     if (packet.hasHeader(tcp)) {
>         Packet persisted = packet.persist();
>         workQueue.offer(persisted);
>     }
> });
> 
> // Worker thread (each needs own header instances)
> void workerThread() {
>     Ip4 ip4 = new Ip4();  // Thread-local headers
>     Tcp tcp = new Tcp();
>     
>     while (running) {
>         Packet packet = workQueue.poll(100, TimeUnit.MILLISECONDS);
>         if (packet != null) {
>             if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
>                 // Process...
>             }
>             packet.recycle();
>         }
>     }
> }
> ```
>
> ### Advanced
>
> **PcapDumperExample** - Write packets to file
>
> ```java
> try (NetPcap pcap = NetPcap.create(device, settings)) {
>     pcap.activate();
>     
>     try (PcapDumper dumper = pcap.dumpOpen("output.pcap")) {
>         pcap.dispatch(100, packet -> {
>             MemorySegment hdr = packet.descriptor().boundMemory().segment();
>             MemorySegment pkt = packet.boundMemory().segment();
>             dumper.dump(hdr, pkt);
>         });
>         dumper.flush();
>     }
> }
> ```
>
> **RawPcapCapture** - Low-level Pcap bindings without dissection
>
> ```java
> Pcap.activateLicense();
> 
> try (Pcap pcap = Pcap.create(device)) {
>     pcap.activate();
>     
>     PcapHeaderABI abi = pcap.getPcapHeaderABI();
>     
>     pcap.loop(100, (String user, MemorySegment header, MemorySegment data) -> {
>         int capLen = abi.captureLength(header);
>         long tsSec = abi.tvSec(header);
>         // Direct memory access...
>     }, "");
> }
> ```
>
> ## Key Concepts
>
> ### Configuration Separation
>
> jNetPcap separates two configuration concerns:
>
> | Configuration       | Purpose            | Examples                          |
> | ------------------- | ------------------ | --------------------------------- |
> | **NetPcap setters** | Capture properties | snaplen, timeout, filter, promisc |
> | **PacketSettings**  | Packet structure   | dissection mode, memory strategy  |
>
> ```java
> // PacketSettings - how packets are structured
> PacketSettings settings = new PacketSettings().dissect();
> 
> try (NetPcap pcap = NetPcap.create("eth0", settings)) {
>     // NetPcap setters - capture properties
>     pcap.setSnaplen(65535)
>         .setTimeout(Duration.ofSeconds(1))
>         .setPromisc(true)
>         .activate();
> 
>     pcap.setFilter("tcp port 80");
>     pcap.loop(-1, handler);
> }
> ```
>
> ### Header Reuse Pattern
>
> Headers are pre-allocated and reused across packets for zero-allocation processing:
>
> ```java
> // Allocate once, outside the loop
> final Ip4 ip4 = new Ip4();
> final Tcp tcp = new Tcp();
> 
> pcap.dispatch(packet -> {
>     // hasHeader() binds the header to packet data
>     if (packet.hasHeader(ip4)) {
>         System.out.println(ip4.src());
>     }
> });
> ```
>
> ### Packet Persistence
>
> Packets in callbacks are bound to native buffers and only valid within the callback:
>
> | Method            | Use Case                   | Memory               |
> | ----------------- | -------------------------- | -------------------- |
> | `persist()`       | Queue for later processing | Copies to new buffer |
> | `persistTo(pool)` | High-volume capture        | Uses pool memory     |
> | `copy()`          | Independent lifecycle      | Full deep copy       |
> | `recycle()`       | Return pooled packet       | Returns to pool      |
>
> ### Thread Safety
>
> - **NetPcap/Pcap**: Single-threaded only
> - **Header instances**: Not thread-safe, use per-thread instances
> - **Persisted packets**: Safe to pass between threads
>
> ## What's Included
>
> The `jnetpcap-sdk` dependency provides:
>
> | Module             | Description                                 |
> | ------------------ | ------------------------------------------- |
> | jnetpcap-api       | High-level NetPcap API                      |
> | jnetpcap-bindings  | libpcap FFM bindings                        |
> | sdk-protocol-core  | Packet, Header, PacketSettings, descriptors |
> | sdk-protocol-tcpip | Ethernet, IPv4/6, TCP, UDP                  |
>
> ### Optional Protocol Packs
>
> For additional protocols, add explicitly:
>
> ```xml
> <!-- HTTP, TLS, QUIC, HTTP/2, HTTP/3 -->
> <dependency>
>     <groupId>com.slytechs.sdk</groupId>
>     <artifactId>sdk-protocol-web</artifactId>
>     <version>3.0.0</version>
> </dependency>
> 
> <!-- Routing, STP, discovery protocols -->
> <dependency>
>     <groupId>com.slytechs.sdk</groupId>
>     <artifactId>sdk-protocol-infrastructure</artifactId>
>     <version>3.0.0</version>
> </dependency>
> ```
>
> ## Example Files
>
> The repository includes sample pcap files in the `pcaps/` directory:
>
> | File                              | Description            |
> | --------------------------------- | ---------------------- |
> | HTTP.cap                          | HTTP traffic           |
> | varied-traffic-capture-lan.pcapng | Mixed LAN traffic      |
> | IPv4-ipf.pcapng                   | IPv4 fragmentation     |
> | IPv4-ipf2.pcapng                  | IPv4 fragmentation     |
> | ipv6-udp-fragmented.pcap          | IPv6 UDP fragmentation |
> | 6to4.pcap                         | IPv6 tunneling         |
> | sr-header.pcap                    | Segment routing        |
>
> ## Resources
>
> - [jNetPcap SDK](https://github.com/slytechs-repos/jnetpcap-sdk) - Main SDK repository
> - [API Documentation](https://docs.slytechs.com/jnetpcap) - Javadoc
> - [Sly Technologies](https://www.slytechs.com/) - Company website
>
> ## License
>
> Apache License 2.0
