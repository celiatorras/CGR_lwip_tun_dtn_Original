#ifndef DTN_CONTROLLER_H
#define DTN_CONTROLLER_H

#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "dtn_module.h"
#include <stdbool.h> 

#define MAX_DESTINATIONS 10
#define FORWARDING_RETRY_DELAY_MS 30000  // 30 seconds delay between retransmissions

// Structure to track forwarding attempts
typedef struct {
    ip6_addr_t destination;
    u32_t last_attempt_time;
    bool is_valid;
} ForwardingAttempt;

typedef struct DTN_Controller {
    DTN_Module* parent_module;
    ForwardingAttempt forwarding_attempts[MAX_DESTINATIONS];
} DTN_Controller;

DTN_Controller* dtn_controller_create(DTN_Module* parent);
void dtn_controller_destroy(DTN_Controller* controller);
void dtn_controller_process_incoming(DTN_Controller* controller, struct pbuf *p, struct netif *inp_netif);
void dtn_controller_attempt_forward_stored(DTN_Controller* controller, struct netif *netif_out);
void dtn_controller_remove_tracking(DTN_Controller* controller, const ip6_addr_t* dest_addr);

int dtn_controller_process_icmpv6(DTN_Controller* controller, struct pbuf *p, struct netif *inp_netif);

#endif