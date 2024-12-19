/*
 * Copyright (c) 2022-2024 Sly Technologies Inc.
 */

/**
 * Various <em>jNetPcap</em> and <em>jNetPcap Pro</em> examples.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
module com.slytechs.jnetpcap.example {

	// Low level libpcap wrapper
	requires org.jnetpcap;
	
	// High level protocol enabled API
	requires com.slytechs.jnet.jnetpcap.api;
	
	requires com.slytechs.jnet.jnetruntime;
	requires com.slytechs.jnet.protocol;
	requires com.slytechs.jnet.protocol.web;

}