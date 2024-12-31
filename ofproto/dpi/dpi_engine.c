/*
 * dpi-engine.c
 *
 *  Created on: 03-Apr-2015
 *      Author: kspviswa
 */



#include <stdio.h>
#include <string.h>
#include "dpi-interface.h"
#include "dpi_plugin.h"
#include "openvswitch/vlog.h"

//Register this module
VLOG_DEFINE_THIS_MODULE(dpi_engine);


void dpiInit(char *sampleIp, char *kafkaBroker)
{
	VLOG_DBG("%s %d", __FUNCTION__, __LINE__);
	VLOG_INFO("%s %d sampleIp:%s, kafkaBroker:%s.",  __FUNCTION__, __LINE__, sampleIp, kafkaBroker);
	engine_init(sampleIp, kafkaBroker);
}

uint32_t dpiProcessPacket(void *packet, uint32_t nSize, int inPort)
{
	VLOG_DBG("%s %d", __FUNCTION__, __LINE__);
	return engine_process(packet, nSize, inPort);
}

void dpiExit(void)
{
	VLOG_DBG("%s %d", __FUNCTION__, __LINE__);
	engine_destroy();
}
