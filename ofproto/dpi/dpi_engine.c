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

//Globals
void *dpiLib = NULL;

void dpiInit(void)
{
	VLOG_DBG("%s %d", __FUNCTION__, __LINE__);
	engine_init();VLOG_INFO("%s %d", __FUNCTION__, __LINE__);
}

uint32_t dpiProcessPacket(void *packet, uint32_t nSize)
{
	VLOG_DBG("%s %d", __FUNCTION__, __LINE__);
	return engine_process(packet, nSize);
}

void dpiExit(void)
{
	VLOG_DBG("%s %d", __FUNCTION__, __LINE__);
	engine_destroy();
}
