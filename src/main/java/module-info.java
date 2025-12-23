/*
 * Copyright (c) 2022-2024 Sly Technologies Inc.
 */

/**
 * Various <em>jNetPcap</em> and <em>jNetPcap Pro</em> examples.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
module com.slytechs.jnetpcap.examples {

	// Low level libpcap wrapper
	requires com.slytechs.sdk.jnetpcap;
	
	// High level protocol enabled API
	requires com.slytechs.sdk.jnetpcap.api;
	
	requires com.slytechs.sdk.common;
	requires com.slytechs.sdk.protocol.core;

}