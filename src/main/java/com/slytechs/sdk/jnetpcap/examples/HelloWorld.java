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
package com.slytechs.sdk.jnetpcap.examples;

import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.jnetpcap.api.NetPcap;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

public class HelloWorld {

	public static void main(String[] args) throws PcapException {
		NetPcap.activateLicense(); // Free community license

		Ip4 ip4 = new Ip4();
		Tcp tcp = new Tcp();

		try (var pcap = NetPcap.openOffline("capture.pcap")) {
			pcap.loop(-1, packet -> {
				if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
					System.out.printf("%s:%d → %s:%d%n",
							ip4.src(), tcp.srcPort(),
							ip4.dst(), tcp.dstPort());
				}
			});
		}
	}
}