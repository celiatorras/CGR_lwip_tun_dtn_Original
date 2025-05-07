// dtn_routing.h
#ifndef DTN_ROUTING_H
#define DTN_ROUTING_H

#include "dtn_module.h"
#include "lwip/ip6_addr.h"
#include <stdbool.h> 

// Routing function structure
typedef struct Routing_Function {
    DTN_Module* parent_module;
    char* routing_algorithm_name;
    bool contact_available_for_dtn_node;
    // Add routing-specific state later (e.g., contact graph, DTN neighbor list)
} Routing_Function;

Routing_Function* dtn_routing_create(DTN_Module* parent);

void dtn_routing_destroy(Routing_Function* routing);

bool dtn_routing_is_dtn_destination(Routing_Function* routing, const ip6_addr_t* dest_ip);

int dtn_routing_get_dtn_next_hop(Routing_Function* routing, const ip6_addr_t* dest_ip, ip6_addr_t* next_hop_ip); // Renamed for clarity

void dtn_routing_set_contact_availability(Routing_Function* routing, bool available); 

#endif // DTN_ROUTING_H