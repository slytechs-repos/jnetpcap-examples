/*
 * Copyright 2005-2025 Sly Technologies Inc.
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

import java.util.List;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.sdk.jnetpcap.PcapException;
import com.slytechs.sdk.jnetpcap.PcapIf;

/**
 * Example 17: Interface Enumeration
 * 
 * Lists all available network interfaces with their properties:
 * - Name and description
 * - Flags (up, running, loopback, wireless)
 * - IP addresses (IPv4 and IPv6)
 * 
 * Useful for discovering which interfaces are available for capture
 * and selecting the appropriate one programmatically.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class InterfaceEnumeration {

    public static void main(String[] args) throws PcapException {
        new InterfaceEnumeration().run();
    }

    public void run() throws PcapException {
        System.out.println("=== Available Network Interfaces ===");
        System.out.println();

        List<PcapIf> devices = NetPcap.findAllDevs();

        if (devices.isEmpty()) {
            System.out.println("No network interfaces found.");
            System.out.println("Note: On some systems, elevated privileges are required.");
            return;
        }

        System.out.printf("Found %d interface(s):%n", devices.size());
        System.out.println();

        int index = 0;
        for (PcapIf dev : devices) {
            index++;
            System.out.printf("[%d] %s%n", index, dev.name());

            // Description (may be null)
            if (dev.description() != null && !dev.description().isEmpty()) {
                System.out.printf("    Description: %s%n", dev.description());
            }

            // Flags
            System.out.print("    Flags: ");
            printFlags(dev);
            System.out.println();

            // Addresses
            var addresses = dev.addresses();
            if (addresses != null && !addresses.isEmpty()) {
                System.out.println("    Addresses:");
                for (var addr : addresses) {
                    var sockAddr = addr.socketAddress();
                    if (sockAddr != null) {
                        System.out.printf("      %s%n", sockAddr);
                        addr.netmask().ifPresent(nm -> 
                            System.out.printf("        Netmask: %s%n", nm));
                        addr.broadcast().ifPresent(bc -> 
                            System.out.printf("        Broadcast: %s%n", bc));
                    }
                }
            }

            System.out.println();
        }

        // Summary: recommend best interface for capture
        System.out.println("=== Recommended Interface ===");
        PcapIf recommended = devices.stream()
                .filter(d -> d.isUp() && d.isRunning() && !d.isLoopback())
                .findFirst()
                .orElse(null);

        if (recommended != null) {
            System.out.printf("Best for capture: %s%n", recommended.name());
            recommended.description().ifPresent(desc -> 
                System.out.printf("  (%s)%n", desc));
        } else {
            System.out.println("No suitable interface found for capture.");
            System.out.println("Look for an interface that is UP, RUNNING, and not LOOPBACK.");
        }
    }

    private void printFlags(PcapIf dev) {
        StringBuilder flags = new StringBuilder();

        if (dev.isUp()) flags.append("UP ");
        if (dev.isRunning()) flags.append("RUNNING ");
        if (dev.isLoopback()) flags.append("LOOPBACK ");

        // Use flagsAsEnumSet for additional flags
        var flagSet = dev.flagsAsEnumSet();
        System.out.print(flags.toString().trim());
        if (!flagSet.isEmpty()) {
            System.out.print(" " + flagSet);
        }
    }
}