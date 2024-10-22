
#ifndef DPIF_SONIC_H
#define DPIF_SONIC_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dpif.h"
#include "openvswitch/types.h"
#include "dp-packet.h"
#include "packets.h"

#ifdef  __cplusplus
extern "C" {
#endif

bool dpif_is_sonic(const struct dpif *);

#ifdef  __cplusplus
}
#endif

#endif /* DPIF_SONIC_H */