/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnet.jnetpcap.example;

import org.jnetpcap.PcapException;

import com.slytechs.jnet.jnetpcap.NetPcap;
import com.slytechs.jnet.jnetruntime.util.Detail;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.constants.IpfDescriptorType;
import com.slytechs.jnet.protocol.descriptor.IpfReassembly;
import com.slytechs.jnet.protocol.meta.PacketFormat;

/**
 * The example shows how to use PcapPro's IPv4 and IPv6 fragmentation reassembly
 * feature.
 * 
 *  * <pre>
 * struct pack_record_s {
 * 	uint32_t
 * 		ordinal:4,  // Index within the protocol pack
 *      base:4
 * 		pack:4,     // Protocol pack unique number
 * 		size:11,    // (Optional) Size of the protocol header (in units of 32-bits)
 * 		offset:11;  // (Optional) Offset into the packet (in units of 8-bit bytes)
 * }
 * </pre>
 */
public class Example5_IpFragmentReassembly {
	
	/** Bootstrap the example */
	public static void main(String[] args) throws PcapException {
		new Example5_IpFragmentReassembly().main();
	}

	/** Main example */
	void main() throws PcapException {
		final String IP_FRAGMENTED_FILE = "pcaps/IPv4-ipf.pcapng";
//		final String IP_FRAGMENTED_FILE = "pcaps/IPv4-ipf2.pcapng";
		final String LAN_FILE = "pcaps/LAN-1.pcapng";
		final String IP6_FILE = "pcaps/sr-header.pcap";

//		try (PcapPro pcapPro = PcapPro.openOffline(IP6_FILE)) {
//		try (PcapPro pcapPro = PcapPro.openOffline(LAN_FILE)) {
		try (NetPcap pcap = NetPcap.openOffline(IP_FRAGMENTED_FILE)) {

//			pcap.installProcessor(PacketPlayer::new)
//					.enableIf(pcap.getPcapType()::isOffline)
//					.preserveIfg(true) // Preserve inter-frame-gap
//					.syncTimestamp(true) // Sync timestamp to first frame, otherwise sync to current time
//					.play(1); // 1 = preserve original inter-frame-gap, otherwise adjust it accordingly
//
//			/* Enable IP fragmentation reassembly and use many IPF options */
//			pcap.installPost(IpfReassembler::new)
//					.enable(true) // Enables both IPF reassembly and tracking
//					.enableReassembly(true) // Default, but this is how you disable
//					.enableTracking(true) // Default, but this is how you disable
//					.enablePassthrough(true) // Pass through original IP fragments
//					.enableAttachComplete(true) // Attach only complete dgrams to last IPF
//					.enableAttachIncomplete(true) // Attach incomplete dgrams as well to last IPF
//					.enableSend(true) // Enable sending new IP datagrams in packet stream
//					.enableSendComplete(true) // Send new reassembled dgrams
//					.enableSendIncomplete(true) // Send new incomplete dgrams
//					.setTimeoutOnLast(true) // Otherwise only timeout on duration
//					.setBufferSize(9, MemoryUnit.MEGABYTES) // Total reassembly buffer size
//					.setTableSize(1, CountUnit.KILO) // How many hash table entries
//					.setTableMaxFragmentCount(32) // Max number of IP fragments per hash entry
//					.setTimeoutMilli(1200) // Timeout in system or packet time for incomplete dgrams
//					.setMaxDgramSize(9, MemoryUnit.KILOBYTES) // Max reassembled IP dgram size
//					.usePacketTimesource(); // vs System timesource

			pcap
//					.uninstallAll()
					.setPacketFormatter(new PacketFormat())
					.activate();

			pcap.dispatch((Packet packet) -> {
				IpfReassembly reassemblyDesc = packet.descriptor(IpfDescriptorType.IPF_REASSEMBLY);

//				System.out.println(packet.toString(Detail.HIGH));

//				if (reassemblyDesc != null)
//					System.out.println(reassemblyDesc.toString(Detail.HIGH));

				if (packet.descriptor().frameNo() == 8)
					System.out.println(packet.toString(Detail.HIGH)); // Full pretty formatting by default
				
//				System.out.println(packet.peekHeader(new Icmp4()));

//				System.out.println(packet.descriptor().toString(Detail.HIGH));
			});
		}
	}

	/** Main example */
	void mainCutPasteReadyCode() throws PcapException {

		try (NetPcap pcap = NetPcap.openOffline("IPv4-ipf.pcapng")) {

			/*
			 * Enable IP Fragment (IPF) reassembly and activate offline capture
			 */
			pcap.enableIpf(true);
			pcap.activate();

			/*
			 * Display reassembled packets
			 * 
			 * Java method reference equivalent to lamda expression:
			 * 
			 * (Packet packet) -> System.out.println(packet)
			 */
			pcap.dispatch(System.out::println);
		}

	}
}
