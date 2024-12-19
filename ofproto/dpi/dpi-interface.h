/*
 * dpi-interface.h
 *
 *  Created on: 03-Apr-2015
 *      Author: kspviswa
 */

#include <stdint.h>
#ifndef DPI_INTERFACE_H_
#define DPI_INTERFACE_H_


/**
 * This is the generic interface for any DPI engine, that is pluggable to ovs.
 * Any 3rd party DPI adhering to this interface can be plugged to ovs.
 *
 * As of now, this interface accepts only ethernet packets.
 *
 */


// library init
void dpiInit(void);

// Process ethernet packet for DPI
// DPI implementing library should convert the void *packet to ethernet packet
uint32_t dpiProcessPacket(void *packet, uint32_t nSize);

// library exit
void dpiExit(void);

#endif /* DPI_INTERFACE_H_ */
