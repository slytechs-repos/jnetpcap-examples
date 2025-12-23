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
package com.slytechs.sdk.jnetpcap.examples;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.jnetpcap.PcapException;

import com.slytechs.jnet.jnetpcap.api.NetPcap;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class Example6_smallest_footprint {
	final String LAN_FILE = "pcaps/LAN-1.pcapng";

	/**
	 * Bootstrap the example
	 * 
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public static void main(String[] args) throws PcapException, FileNotFoundException, IOException {
		new Example6_smallest_footprint().main();
	}

	/**
	 * Shortest example possible.
	 *
	 * @throws PcapException         the pcap exception
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	void main() throws PcapException, FileNotFoundException, IOException {

		try (var pcap = NetPcap.offline("pcaps/IPv4-ipf.pcapng")) {
			pcap.dispatchPacket(System.out::println);
		}

	}
}
