/*
 * dpi_plugin.h
 *
 *  Created on: 04-Apr-2015
 *      Author: kspviswa
 */

#ifndef DPI_PLUGIN_H_
#define DPI_PLUGIN_H_


typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;


int engine_init(char *sampleIp, char *kafkaBroker);
int engine_destroy(void);
int engine_process(void *packet, uint32_t nSize, int inPort);

#endif /* DPI_PLUGIN_H_ */
