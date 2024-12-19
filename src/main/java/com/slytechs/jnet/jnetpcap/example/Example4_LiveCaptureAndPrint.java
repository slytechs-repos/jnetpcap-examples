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

import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.jnet.jnetruntime.util.MemoryUnit;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.api.packet.Packet;
import com.slytechs.jnet.protocol.tcpip.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.tcpip.network.Ip4;
import com.slytechs.jnet.protocol.tcpip.transport.Tcp;
import com.slytechs.jnet.protocol.web.Html;
import com.slytechs.jnet.protocol.web.Http;

/**
 * Pcap packet capture and reassembly example using jNetPcap.
 */
public class Example4_LiveCaptureAndPrint {

	private static final Ip4 ip4 = new Ip4();
	private static final Tcp tcp = new Tcp();
	private static final Http http = new Http();
	private static final Html html = new Html();

	/** Example instance */
	public static void main(String[] args) throws PcapException {

		List<PcapIf> deviceList = Pcap.findAllDevs();
		PcapIf device = deviceList.get(0);

		System.out.println("Opening device '%s'".formatted(device.name()));

		try (NetPcap pcap = NetPcap.live(device)) {

			/* Pro API! Set packet descriptor type and pretty print formatter */
			pcap
					.setDescriptorType(PacketDescriptorType.TYPE2)
					.setPacketFormatter(new PacketFormat())
					.setBufferSize(4, MemoryUnit.KILOBYTES)
					.setNonBlock(true)
					.activate();

			/* Number of packets to capture */
			final int PACKET_COUNT = 0;

			pcap.dispatchPacket(PACKET_COUNT, Example4_LiveCaptureAndPrint::nextPacket, "Example4");
		}
	}

	/* Out packet handler */
	private static void nextPacket(String user, Packet packet) {

		if (packet.hasHeader(ip4))
			System.out.println(ip4);

		if (packet.hasHeader(tcp))
			System.out.println(tcp);

		if (packet.hasHeader(http))
			System.out.println(http);

		if (packet.hasHeader(http))
			System.out.println(http);

		if (packet.hasHeader(html))
			System.out.println(html);

	}
}
