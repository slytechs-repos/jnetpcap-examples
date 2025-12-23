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
> ### Running Examples
>
> ```bash
> # Clone the repository
> git clone https://github.com/slytechs-repos/jnetpcap-examples.git
> cd jnetpcap-examples
> 
> # Run a specific example
> mvn compile exec:java -Dexec.mainClass="com.slytechs.sdk.jnetpcap.examples.Example1_CapturePacketsAndPrintHeaders"
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
> **Example1_CapturePacketsAndPrintHeaders** - Offline capture with protocol header inspection
>
> ```java
> try (NetPcap pcap = NetPcap.openOffline("capture.pcap")) {
>     
>     // Pre-allocate headers for zero-allocation access
>     final Ethernet ethernet = new Ethernet();
>     final Ip4 ip4 = new Ip4();
>     final Tcp tcp = new Tcp();
> 
>     pcap.dispatch(10, (String user, Packet packet) -> {
>         
>         if (packet.hasHeader(ethernet))
>             System.out.println(ethernet);
> 
>         if (packet.hasHeader(ip4))
>             System.out.println(ip4);
> 
>         if (packet.hasHeader(tcp))
>             System.out.println(tcp);
> 
>     }, "Example1");
> }
> ```
>
> **Example6_smallest_footprint** - Minimal code to capture and print packets
>
> ```java
> try (var pcap = NetPcap.openOffline("capture.pcap")) {
>     pcap.dispatch(System.out::println);
> }
> ```
>
> ### Live Capture
>
> **Example2_LiveCaptureAndFiltering** - Live capture with BPF filtering
>
> ```java
> try (NetPcap pcap = NetPcap.openLive()) {
>     pcap.setSnaplen(2048)
>         .setTimeout(10_000)
>         .setPromiscuous(true)
>         .activate();
> 
>     pcap.setFilter("tcp port 80");
> 
>     pcap.dispatch(100, (String user, Packet packet) -> {
>         // Process packets...
>     }, "LiveCapture");
> }
> ```
>
> ### Raw Packet Access
>
> **Example3_FilterRawPackets** - Low-level access using base Pcap API
>
> ```java
> try (Pcap pcap = Pcap.openOffline("capture.pcap")) {
>     pcap.setFilter(pcap.compile("tcp", true));
> 
>     pcap.dispatch(10, (String user, MemorySegment header, MemorySegment packet) -> {
>         // Direct memory access to packet data
>     }, "RawCapture");
> }
> ```
>
> ### Protocol Analysis
>
> **UsecaseIcmpTypeLookup** - Working with ICMP message types
>
> ```java
> final Icmp4 icmp4 = new Icmp4();
> final Icmp4Echo echo = new Icmp4Echo();
> 
> pcap.dispatch(packet -> {
>     if (packet.hasHeader(icmp4)) {
>         System.out.printf("ICMP type=%d code=%d%n", icmp4.type(), icmp4.code());
>     }
>     
>     if (packet.hasHeader(echo)) {
>         System.out.printf("Echo id=%d seq=%d%n", echo.id(), echo.sequence());
>     }
> });
> ```
>
> ## Key Concepts
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
>         // ip4 now references this packet's IPv4 header
>         System.out.println(ip4.src());  // Source IP
>     }
> });
> // After dispatch returns, headers are unbound
> ```
>
> ### Header Lifecycle
>
> Headers are only valid within the dispatch callback. After the callback returns, headers are unbound and must not be accessed. To retain header data beyond the callback, use `clone()`:
>
> ```java
> Ip4 savedHeader = null;
> 
> pcap.dispatch(packet -> {
>     if (packet.hasHeader(ip4)) {
>         savedHeader = ip4.clone();  // Deep copy, safe to use later
>     }
> });
> ```
>
> ### Packet Descriptor
>
> Every packet includes a descriptor with capture metadata:
>
> ```java
> pcap.dispatch(packet -> {
>     var desc = packet.descriptor();
>     
>     System.out.printf("Frame #%d: caplen=%d wirelen=%d timestamp=%s%n",
>         desc.frameNo(),
>         packet.captureLength(),
>         packet.wireLength(),
>         packet.timestamp());
> });
> ```
>
> ## What's Included
>
> The `jnetpcap-sdk` dependency provides:
>
> | Module             | Description                      |
> | ------------------ | -------------------------------- |
> | jnetpcap-api       | High-level NetPcap API           |
> | jnetpcap-bindings  | libpcap FFM bindings             |
> | sdk-protocol-core  | Dissection framework             |
> | sdk-protocol-tcpip | Ethernet, IPv4/6, TCP, UDP, ICMP |
>
> ### Optional Protocol Packs
>
> For additional protocols, add explicitly:
>
> ```xml
> <!-- HTTP, TLS, DNS over HTTPS -->
> <dependency>
>     <groupId>com.slytechs.sdk</groupId>
>     <artifactId>sdk-protocol-web</artifactId>
>     <version>3.0.0</version>
> </dependency>
> ```
>
> ## Source Code
>
> Browse the example source:
>
> - [Basic Examples](https://claude.ai/chat/src/main/java/com/slytechs/sdk/jnetpcap/examples/)
> - [Use Cases](https://claude.ai/chat/src/main/java/com/slytechs/sdk/jnetpcap/examples/usecase/)
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
