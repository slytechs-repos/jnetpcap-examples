/*
 * Copyright 2005 Sly Technologies Inc
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

/**
 * Example module for jNetPcap SDK demonstrations.
 *
 * <p>
 * This module contains runnable examples that showcase the capabilities of
 * jNetPcap v3 — a high-performance Java library for packet capture and protocol
 * dissection built on libpcap/winpcap using Java's Foreign Function & Memory API.
 * </p>
 *
 * <p>
 * The examples focus on:
 * </p>
 * <ul>
 *   <li>Modern capture workflow using {@code NetPcap.create()} and {@code activate()}</li>
 *   <li>Zero-allocation header binding and protocol dissection</li>
 *   <li>Integration with the shared protocol stack for advanced features</li>
 *   <li>Best practices for configuration, filtering, and resource management</li>
 * </ul>
 *
 * <p>
 * jNetPcap is strictly single-threaded by design, mirroring libpcap semantics.
 * For multi-threaded or ultra-high-throughput needs, see the companion
 * jNetWorks SDK.
 * </p>
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 * @since 3.0.0
 */
module com.slytechs.jnetpcap.examples {

    requires com.slytechs.sdk.jnetpcap.api;
    requires com.slytechs.sdk.common;
    requires com.slytechs.sdk.protocol.core;
    requires com.slytechs.sdk.protocol.tcpip;

}