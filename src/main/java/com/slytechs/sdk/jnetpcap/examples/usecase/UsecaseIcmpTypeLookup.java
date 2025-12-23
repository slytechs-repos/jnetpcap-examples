/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.sdk.jnetpcap.examples.usecase;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.jnetpcap.PcapException;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp4;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp4Echo;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6Echo;

/**
 * Different use-cases of checking for various ICMP types efficiently.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class UsecaseIcmpTypeLookup {

	static final String FILENAME = "pcaps/IPv4-ipf.pcapng";

	public static void main(String[] args) throws PcapException, FileNotFoundException, IOException {
//		new UsecaseIcmpTypeLookup().usecase1_byNumericalVersionAndType();
//		new UsecaseIcmpTypeLookup().usecase2_byIcmpHeaderPeerVersion();
		new UsecaseIcmpTypeLookup().usecase3_bySpecificIcmpHeaderTypes();
	}

	void usecase1_byNumericalVersionAndType() throws PcapException, FileNotFoundException, IOException {
		final Icmp icmp = new Icmp();

		try (var pcap = NetPcap.offline(FILENAME)) {

			pcap.dispatchPacket(packet -> {
				if (!packet.hasHeader(icmp))
					return;

				if (icmp.version() == 4)
					switch (icmp.type()) {
					}
				else if (icmp.version() == 6)
					switch (icmp.type()) {
					}
			});

		}
	}

	void usecase2_byIcmpHeaderPeerVersion() throws PcapException, FileNotFoundException, IOException {
		final Icmp4 icmp4 = new Icmp4();
		final Icmp6 icmp6 = new Icmp6();

		try (var pcap = NetPcap.offline(FILENAME)) {

			pcap.dispatchPacket(packet -> {
				if (packet.hasHeader(icmp4))
					switch (icmp4.type()) {
					}

				else if (packet.hasHeader(icmp6))
					switch (icmp6.type()) {
					}

			});

		}
	}

	void usecase3_bySpecificIcmpHeaderTypes() throws PcapException, FileNotFoundException, IOException {
		final Icmp4 icmp4 = new Icmp4();
		final Icmp6 icmp6 = new Icmp6();
		final Icmp4Echo echo = new Icmp4Echo();
		final Icmp4Echo.Request echoRequest4 = new Icmp4Echo.Request();
		final Icmp6Echo echo6 = new Icmp6Echo();

		try (var pcap = NetPcap.offline(FILENAME)) {

			pcap.dispatchPacket(packet -> {

				System.out.println(packet.descriptor().toString(Detail.HIGH));
//					System.out.println(packet);

				if (packet.hasHeader(icmp4)) {
					System.out.println(icmp4.toString(Detail.HIGH));
				}

				if (packet.hasHeader(echo)) {
					System.out.println(echo.toString(Detail.HIGH));
				}

				if (packet.hasHeader(echoRequest4)) {
//					System.out.println(echoRequest4.toString(Detail.HIGH));

				} else if (packet.hasHeader(echo6)) {
					System.out.println(echo6.toString(Detail.HIGH));

				}

			});

		}
	}
}
