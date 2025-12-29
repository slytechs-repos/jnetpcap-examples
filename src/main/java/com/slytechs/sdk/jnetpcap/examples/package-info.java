/*
 * Licensed under the Apache License, Version 2.0 - see http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Example programs demonstrating usage of the jNetPcap SDK.
 *
 * <p>
 * These standalone examples illustrate core features of jNetPcap v3, including:
 * </p>
 * <ul>
 * <li>Live and offline packet capture using the modern
 * {@code create() → activate()} pattern</li>
 * <li>Zero-allocation protocol header access via {@code hasHeader()}</li>
 * <li>Integration with
 * {@link com.slytechs.sdk.protocol.core.stack.ProtocolStack} for advanced
 * dissection and reassembly</li>
 * <li>Configuration of capture parameters (snaplen, filters, timeouts)</li>
 * <li>Safe resource management with try-with-resources</li>
 * </ul>
 *
 * <p>
 * All examples are designed to be simple, runnable, and educational. They
 * follow best practices and showcase the preferred API usage patterns.
 * </p>
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 * @since 3.0.0
 */
package com.slytechs.sdk.jnetpcap.examples;