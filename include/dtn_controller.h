#ifndef DTN_CONTROLLER_H
#define DTN_CONTROLLER_H

#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "dtn_module.h"

typedef struct DTN_Controller {
    DTN_Module* parent_module;
} DTN_Controller;


DTN_Controller* dtn_controller_create(DTN_Module* parent);
void dtn_controller_destroy(DTN_Controller* controller);
void dtn_controller_process_incoming(DTN_Controller* controller, struct pbuf *p, struct netif *inp_netif);

void dtn_controller_attempt_forward_stored(DTN_Controller* controller, struct netif *netif_out);

#endif // DTN_CONTROLLER_H