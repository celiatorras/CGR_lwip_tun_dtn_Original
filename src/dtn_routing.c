#include "dtn_routing.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <stdbool.h>
#include "lwip/ip6_addr.h"

#define TARGET_DTN_NODE_ADDR "fd00:44::2"

Routing_Function* dtn_routing_create(DTN_Module* parent) {
    Routing_Function* routing = (Routing_Function*)malloc(sizeof(Routing_Function));
    if (routing) {
        routing->parent_module = parent;
        routing->routing_algorithm_name = "Placeholder (e.g., CGR)";
        routing->contact_available_for_dtn_node = false; 
        printf("DTN Routing Function created. Contact for %s initially: %s\n",
               TARGET_DTN_NODE_ADDR, routing->contact_available_for_dtn_node ? "ON" : "OFF");
    } else {
        perror("Failed to allocate memory for Routing_Function");
    }
    return routing;
}

void dtn_routing_destroy(Routing_Function* routing) {
    if (!routing) return;
    printf("Destroying DTN Routing Function...\n");
    free(routing);
}

void dtn_routing_set_contact_availability(Routing_Function* routing, bool available) {
    if (routing) {
        routing->contact_available_for_dtn_node = available;
        printf("DTN Routing: Contact availability for %s set to: %s\n",
               TARGET_DTN_NODE_ADDR, available ? "AVAILABLE" : "UNAVAILABLE");
    }
}

bool dtn_routing_is_dtn_destination(Routing_Function* routing, const ip6_addr_t* dest_ip_in) {
     if (!routing || !dest_ip_in) {
        return false;
    }
    ip6_addr_t local_dest_ip;
    ip6_addr_t target_dtn_node;
    memset(&local_dest_ip, 0, sizeof(ip6_addr_t));
    memset(&target_dtn_node, 0, sizeof(ip6_addr_t));

    memcpy(&local_dest_ip, dest_ip_in, sizeof(ip6_addr_t));

    if (!ip6addr_aton(TARGET_DTN_NODE_ADDR, &target_dtn_node)) {
         fprintf(stderr, "DTN Routing: Failed to parse TARGET_DTN_NODE_ADDR %s!\n", TARGET_DTN_NODE_ADDR);
         return false;
    }

#if LWIP_IPV6_SCOPES
    ip6_addr_set_zone(&local_dest_ip, IP6_NO_ZONE);
    ip6_addr_set_zone(&target_dtn_node, IP6_NO_ZONE);
#endif

    return ip6_addr_cmp(&local_dest_ip, &target_dtn_node);
}


int dtn_routing_get_dtn_next_hop(Routing_Function* routing, const ip6_addr_t* dest_ip, ip6_addr_t* next_hop_ip) {
    if (!routing || !dest_ip || !next_hop_ip) {
        fprintf(stderr, "DTN Routing: Invalid arguments to get_dtn_next_hop.\n");
        return 0;
    }

    if (!dtn_routing_is_dtn_destination(routing, dest_ip)) {
        char dest_addr_str_err[IP6ADDR_STRLEN_MAX];
        ip6addr_ntoa_r(dest_ip, dest_addr_str_err, sizeof(dest_addr_str_err));
        fprintf(stderr, "DTN Routing ERROR: get_dtn_next_hop called for non-DTN dest %s\n", dest_addr_str_err);
        ip6_addr_set_any(next_hop_ip);
        return 0;
    }

    bool contact_is_available = routing->contact_available_for_dtn_node;
    char dest_addr_str[IP6ADDR_STRLEN_MAX];
    ip6addr_ntoa_r(dest_ip, dest_addr_str, sizeof(dest_addr_str));

    if (contact_is_available) {
        printf("DTN Routing: Contact AVAILABLE for DTN destination %s. Providing next hop.\n", dest_addr_str);
        ip6_addr_copy(*next_hop_ip, *dest_ip);
        return 1; 
    } else {
        printf("DTN Routing: Querying next hop for DTN destination %s. (Contact UNAVAILABLE for %s)\n", dest_addr_str, TARGET_DTN_NODE_ADDR);
        ip6_addr_set_any(next_hop_ip);
        return 0; 
    }
}
