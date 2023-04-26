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
package com.slytechs.jnetpcap.examples;

import java.util.Arrays;

import org.jnetpcap.PcapException;

import com.slytechs.jnetpcap.pro.PcapPro;
import com.slytechs.protocol.descriptor.IpfFragment;
import com.slytechs.protocol.pack.core.Ip4;
import com.slytechs.protocol.pack.core.constants.IpfDescriptorType;
import com.slytechs.protocol.runtime.util.CountUnit;
import com.slytechs.protocol.runtime.util.Detail;
import com.slytechs.protocol.runtime.util.MemoryUnit;

/**
 * The example shows how to use PcapPro's IPv4 and IPv6 fragmentation reassembly
 * feature.
 */
public class Example5_IpFragmentReassembly {

	/** Bootstrap the example */
	public static void main(String[] args) throws PcapException {
		new Example5_IpFragmentReassembly().main();
	}

	/** Main example */
	void main() throws PcapException {
		final String IP_FRAGMENTED_FILE = "pcaps/ip-frags.pcapng";

		try (PcapPro pcap = PcapPro.openOffline(IP_FRAGMENTED_FILE)) {

			/* Enable IP fragmentation reassembly and use many IPF options */
			pcap
					.enableIpf(true)
					.enableIpfReassembly(true)
					.enableIpfTracking(true)
					.enableIpfPassthroughFragments(false)
					.enableIpfPassthroughComplete(true)
					.enableIpfAttachComplete(true)
					.enableIpfAttachIncomplete(true)
					.enableIpfPassthroughFragments(true)
					.enableIpfPassthroughComplete(true)
					.enableIpfPassthroughIncomplete(true)
					.setIpfTimeoutOnLast(false) // Otherwise on timeout
					.setIpfBufferSize(1, MemoryUnit.MEGABYTES)
					.setIpfTableSize(16, CountUnit.KILO)
					.setIpfMaxFragmentCount(16)
					.setIpfTimeoutMilli(1200)
					.setIpfMaxDgramSize(64, MemoryUnit.KILOBYTES)
					.useIpfPacketTimesource()
					.activateIpf(); // Or Pcap.activate() if using Pcap.create(...)

			final Ip4 ip4 = new Ip4();

			pcap.dispatch(0, (u, p) -> {
				IpfFragment ipf = p.descriptor(IpfDescriptorType.IPF_FRAG);
				long frameNo = p.descriptor().frameNo();

//				System.out.println(p);
				System.out.printf("%s%n", ipf.toString(Detail.LOW));

				if (p.hasHeader(ip4) && ip4.isTrackingReassembly())
					System.out.println(Arrays.asList(ip4.reassembledFragmentIndexes()));

			}, null);
		}
	}
}
