![Maven Central](https://img.shields.io/maven-central/v/com.slytechs.jnet.jnetpcap.api/jnetpcap-example)

# Examples of jNetPcap API usage
The examples in this modules are a mixture of [**jnetpcap**](https://github.com/slytechs-repos/jnetpcap) and [**jnetpcap-pro**](https://github.com/slytechs-repos/jnetpcap-pro) API usage. Both modules are free, no cost to use in your projects.

**Jump to**: [**Example Source**](https://github.com/slytechs-repos/jnetpcap-examples/tree/main/src/main/java/com/slytechs/jnet/jnetpcap/example/capture)

## Overview
An important aspect of the API to understand, is that in these examples, the main operative class is the `Pcap` class. It is the starting point for nearly all actions when working with **jnetpcap** API. Additionally, the class `PcapPro` is a subclass of `Pcap` class (ie. `class PcapPro extends Pcap`) and provides additional capabilities on top of the base `Pcap` API.

### Dependencies
The examples presented here, rely on several optional modules to be included on the `module path`. The base module **jnetpcap** has no other module dependencies, but the module **jnetpcap-pro** is dependent on **core-protocols** module. Further more the examples here also include **web-protocols** module to demonstrate usage of `Http` header class and its features.

The list of all modules needed to run these examples:
* [**jnetpcap**](https://github.com/slytechs-repos/jnetpcap) module
* [**jnetpcap-pro**](https://github.com/slytechs-repos/jnetpcap-pro) module (to be released by April 7)
* [**core-protocols**](https://github.com/slytechs-repos/core-protocols) module (to be released by April 7)
* [**web-protocols**](https://github.com/slytechs-repos/web-protocols) module (to be released by May 2nd)

### Notes for developers using JDK 19, 20 and 21
To enable support for JDK 19, 20 and 21, a special JDK versioning has been implemented. Please see [notes section](https://github.com/slytechs-repos/slytechs-repos/wiki/9.-Notes) for more information.

### Download Now
Download the [**Latest jnetpcap-examples release**](https://github.com/slytechs-repos/jnetpcap-examples/releases/tag/v0.9-alpha.1) which contains all
of the required JARs to run these examples.

> **Note** **jNetPcap API** applies to both **jnetpcap (Apache License)** and **jnetpcap-pro** modules. However the examples will specify when any particular feature is only available in **jnetpcap-pro API**.

## Offline Packet Capture Examples ([Source Code](https://github.com/slytechs-repos/jnetpcap-examples/tree/main/src/main/java/com/slytechs/jnetpcap/examples))
The examples in this section relate to various ways of capturing packets using **jNetPcap** APIs from offline files or pcap files (both standard and NG file formats).

There are some commonalities to each example. Here are the basic steps:

1. Optionally, check the `Pcap.checkPcapVersion(Pcap.VERSION))` - ensures that the installed pcap runtime is compatible with the version of pcap the application was compiled with
2. Open an offline pcap capture in a `try-with-resource` statement to ensure that proper `Pcap.close` is issued when done using the pcap handle.
    - ie. `try (Pcap pcap = Pcap.openOffline(FILENAME)) {...}`
    - ie. `try (PcapPro pcap = PcapPro.openOffline(FILENAME)) {...}`
3. Optionally, set some parameters on the pcap handle
4. Start packet capture from offline file using either a `Pcap.dispatch(...)` or `Pcap.loop(...)` calls
5. Lastly, provide a packet handler either as a receiving method for the appropriate `PcapHandler` interface or a simple lambda expression

To view all of the **capture** examples [click here](https://github.com/slytechs-repos/jnetpcap-examples/tree/main/src/main/java/com/slytechs/jnet/jnetpcap/example/capture).


### [Example1](https://github.com/slytechs-repos/jnetpcap-examples/blob/main/src/main/java/com/slytechs/jnetpcap/examples/Example2_PacketDescriptorTimestamp.java) - Capture Offline and Pretty Print Packet
The example sets up an offline packet capture, assigns a new packet formatter refered to as "pretty print", which is used to generate formatted constents of packets and headers.

First, we setup a new packet formatter for ``Packet.toString()`` and ``Header.toString()`` outputs.
```java
/* Set a pretty print formatter to toString() method */
pcap.setPacketFormatter(new PacketFormat());
```
Next we allocate various protocol headers. Headers are reusable and they are bound to new packets, one at a time.
```java
/* Pro API! Create protocol headers and reuse inside the dispatch handler */
final Ip4 ip4 = new Ip4();
final Tcp tcp = new Tcp();
final Ip4RouterOption router = new Ip4RouterOption();
```

Our handler is a lambda block code, that receives fully reassembled IP packets. It is also common practice to use a lambda method reference or implementing the handler interface ``OfPacket``.
```java
/* Capture packets and access protocol headers */
pcap.dispatch(PACKET_COUNT, (String user, Packet packet) -> { // Pro API

	// If present, printout ip4 header
	if (packet.hasHeader(ip4))
		System.out.println(ip4);

	// If present, printout IPv4.router header extension
	if (packet.hasHeader(ip4) && ip4.hasExtension(router))
		System.out.println(router);

	// If present, printout tcp header
	if (packet.hasHeader(tcp))
		System.out.println(tcp);

}, "Example2 - Hello World");
```

The first `if` statement checks to see if IPv4 header is present in the packet, if it is, the `Ip4` instance is bound to the memory spanning the contents of IPv4 header. If IPv4 header is found, it is bound and next line prints out the formatted output to console.
The next line is similar and checks for IPv4 header again but this time if found it also checks if IPv4 header contains the IPv4.router option. We can use another header specific for this option `Ip4RouterOption`. If it is, it is also bound just like any other header. If both conditions pass, we have `ip4` and `router` variables bound to their corresponding portions of the IPv4 header. Then we pretty pring the contents of the `router`, or `ip4` header.

Lastly, we check for `Tcp` header and also printout its contents using a pretty print formatter we set before.
> **Important!!!** the lifecycle of the headers and packets inside our handler is only to within the handler itself. Once the example handler returns, the packet and the previously bound headers will be unbound and no longer contain a valid state. If you try to access those object you will likely get an `IllegalStateException`. 
> 
### [Example2](https://github.com/slytechs-repos/jnetpcap-examples/blob/main/src/main/java/com/slytechs/jnetpcap/examples/Example1_CapturePacketsAndPrintHeaders.java) - Simple Packet Capture 
Example 2 demonstrates basic usage of a packet capture using the `PcapProHandler.OfPacket` packet handler. This handler type receives packets which have been dissected for protocol headers present in the capture packet. 

```java
/* Send packets to handler. The generic user parameter can be of any type. */
pcap.loop(PACKET_COUNT, (String user, Packet packet) -> { // Pro API
	System.out.printf("%s: %03d: caplen=%-,5d ts=%s%n",
			user,
			packet.descriptor().frameNo(),
			packet.captureLength(),
			new Timestamp(packet.timestamp(), packet.timestampUnit()));

}, "Example1");
```
The handler is a lambda code block with two arguments. First is an opaque generic user object, in this case a string with a simple message. The second is that `Packet` object containing all of the neccessary information to access packet contents including protocol headers.

> **Note** If you want to copy the packet or the header, you can invoke their `clone()` methods to create a complete duplicate of the data and state.
