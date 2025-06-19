#ifndef DTN_CUSTODY_H
#define DTN_CUSTODY_H

#include "lwip/ip6_addr.h"
#include "lwip/pbuf.h"
#include <stdbool.h>

// Option type for custody transfer header (choose unassigned value)
#define CUSTODY_OPTION_TYPE 0x1E
// Hop-by-Hop header length in bytes (must be multiple of 8)
#define HBH_OPT_HDR_LEN 24

bool dtn_add_custodian_option(struct pbuf **p, const ip6_addr_t *custodian);

bool dtn_extract_custodian_option(const struct pbuf *p, ip6_addr_t *custodian_out);

#endif
