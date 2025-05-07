#include "dtn_controller.h"
#include "dtn_routing.h"  
#include "dtn_storage.h"   
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/pbuf.h"
#include "lwip/err.h"
#include "lwip/netif.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h> 

#define TARGET_DTN_FORWARD_ADDR "fd00:44::2"

DTN_Controller* dtn_controller_create(DTN_Module* parent) {
    DTN_Controller* controller = (DTN_Controller*)malloc(sizeof(DTN_Controller));
    if (controller) {
        controller->parent_module = parent;
        printf("DTN Controller created.\n");
    } else {
        perror("Failed to allocate memory for DTN_Controller");
    }
    return controller;
}

void dtn_controller_destroy(DTN_Controller* controller) {
    if (!controller) return;
    printf("Destroying DTN Controller...\n");
    free(controller);
}


void dtn_controller_process_incoming(DTN_Controller* controller, struct pbuf *p, struct netif *inp_netif) {
    if (!p || !controller || !controller->parent_module ||
        !controller->parent_module->routing || !controller->parent_module->storage) {
        fprintf(stderr, "DTN Controller: Invalid arguments or uninitialized components for incoming.\n");
        if (p) pbuf_free(p);
        return;
    }
    if (p->len < IP6_HLEN) {
        fprintf(stderr, "DTN Controller: Packet too small for IPv6 header.\n");
        pbuf_free(p); return;
    }
    const struct ip6_hdr *ip6hdr = (const struct ip6_hdr *)p->payload;
    if (IP6H_V(ip6hdr) != 6) {
         fprintf(stderr, "DTN Controller: Packet is not IPv6 (version %d).\n", IP6H_V(ip6hdr));
         pbuf_free(p); return;
    }

    ip6_addr_t temp_src_addr, temp_dest_addr;
    memcpy(&temp_src_addr, &ip6hdr->src, sizeof(ip6_addr_t));
    memcpy(&temp_dest_addr, &ip6hdr->dest, sizeof(ip6_addr_t));

    char src_addr_str[IP6ADDR_STRLEN_MAX];
    char dst_addr_str[IP6ADDR_STRLEN_MAX];
    ip6addr_ntoa_r(&temp_src_addr, src_addr_str, sizeof(src_addr_str));
    ip6addr_ntoa_r(&temp_dest_addr, dst_addr_str, sizeof(dst_addr_str));

    printf("DTN Controller: Intercepted packet [%s] -> [%s] (Proto: %d, Len: %d)\n",
           src_addr_str, dst_addr_str, IP6H_NEXTH(ip6hdr), p->tot_len);

    Routing_Function* routing = controller->parent_module->routing;
    Storage_Function* storage = controller->parent_module->storage;

    if (!dtn_routing_is_dtn_destination(routing, &temp_dest_addr)) {
        printf("DTN Controller: Destination %s is not a DTN node. Passing to LwIP.\n", dst_addr_str);
        err_t err = ip6_input(p, inp_netif);
        if (err != ERR_OK) {
            fprintf(stderr, "DTN Controller: ip6_input returned error %d for non-DTN packet.\n", err);
        }
        return;
    }

    printf("DTN Controller: Destination %s IS a DTN node. Checking contact...\n", dst_addr_str);
    ip6_addr_t next_hop_ip;
    int contact_available = dtn_routing_get_dtn_next_hop(routing, &temp_dest_addr, &next_hop_ip);

    if (contact_available) {
        printf("DTN Controller: Contact OPEN for DTN node %s. Passing to LwIP for potential forwarding.\n", dst_addr_str);
        err_t err = ip6_input(p, inp_netif); 
        if (err != ERR_OK) {
            fprintf(stderr, "DTN Controller: ip6_input returned error %d for DTN packet with open contact.\n", err);
        }
    } else {
        printf("DTN Controller: Contact CLOSED for DTN node %s. Attempting to store.\n", dst_addr_str);
        if (dtn_storage_store_packet(storage, p, &temp_dest_addr)) {
            printf("DTN Controller: Packet for %s stored.\n", dst_addr_str);
        } else {
            fprintf(stderr, "DTN Controller: Failed to store packet for %s (e.g., storage full). Freeing.\n", dst_addr_str);
            pbuf_free(p);
        }
    }
}


void dtn_controller_attempt_forward_stored(DTN_Controller* controller, struct netif *netif_out) {
    if (!controller || !controller->parent_module || !controller->parent_module->storage ||
        !controller->parent_module->routing || !netif_out) {
        return; 
    }

    Storage_Function* storage = controller->parent_module->storage;
    Routing_Function* routing = controller->parent_module->routing;

    if (!routing->contact_available_for_dtn_node) {
        return;
    }

    ip6_addr_t dtn_target_node;
    if (!ip6addr_aton(TARGET_DTN_FORWARD_ADDR, &dtn_target_node)) {
        fprintf(stderr, "DTN Controller: Failed to parse TARGET_DTN_FORWARD_ADDR %s!\n", TARGET_DTN_FORWARD_ADDR);
        return;
    }

    Stored_Packet_Entry* retrieved_entry = dtn_storage_retrieve_packet_for_dest(storage, &dtn_target_node);

    if (retrieved_entry && retrieved_entry->p) {
        ip6_addr_t next_hop_ip;
        if (dtn_routing_get_dtn_next_hop(routing, &dtn_target_node, &next_hop_ip)) {
            char target_dest_str[IP6ADDR_STRLEN_MAX];
            ip6addr_ntoa_r(&dtn_target_node, target_dest_str, sizeof(target_dest_str));
            printf("DTN Controller: Contact confirmed AVAILABLE for %s. Processing retrieved packet.\n", target_dest_str);

            char retrieved_dest_str[IP6ADDR_STRLEN_MAX];
            ip6addr_ntoa_r(&retrieved_entry->original_dest, retrieved_dest_str, sizeof(retrieved_dest_str));
            struct pbuf *p_to_fwd = retrieved_entry->p;

            bool is_for_this_lwip_stack = false;
            ip6_addr_t local_lwip_addr;
            if (ip6addr_aton("fd00::2", &local_lwip_addr)) {
                ip6_addr_t retrieved_dest_nozone;
                memcpy(&retrieved_dest_nozone, &retrieved_entry->original_dest, sizeof(ip6_addr_t));
                #if LWIP_IPV6_SCOPES
                    ip6_addr_set_zone(&retrieved_dest_nozone, IP6_NO_ZONE);
                    ip6_addr_set_zone(&local_lwip_addr, IP6_NO_ZONE);
                #endif
                if (ip6_addr_cmp(&retrieved_dest_nozone, &local_lwip_addr)) {
                    is_for_this_lwip_stack = true;
                }
            }

            if (is_for_this_lwip_stack) {
                printf("DTN Controller: Stored packet for this LwIP stack (%s) retrieved. Processing with ip6_input.\n", retrieved_dest_str);
                err_t err = ip6_input(p_to_fwd, netif_out);
                if (err == ERR_OK) {
                    printf("DTN Controller: LwIP successfully processed stored packet for %s.\n", retrieved_dest_str);
                } else {
                    fprintf(stderr, "DTN Controller: Error from ip6_input for stored packet %s: %d.\n",
                            retrieved_dest_str, err);
                    pbuf_free(p_to_fwd);
                }
            } else {
                printf("DTN Controller: Retrieved packet for remote DTN node %s. Attempting forward via linkoutput.\n",
                       retrieved_dest_str);
                err_t err = netif_out->linkoutput(netif_out, p_to_fwd);
                if (err == ERR_OK) {
                    printf("DTN Controller: Packet for %s successfully sent via linkoutput.\n", retrieved_dest_str);
                    pbuf_free(p_to_fwd);
                } else {
                    fprintf(stderr, "DTN Controller: Error sending stored packet for %s via linkoutput: %d.\n",
                            retrieved_dest_str, err);
                    pbuf_free(p_to_fwd);
                }
            }
            dtn_storage_free_retrieved_entry_struct(retrieved_entry);

        } else {
            char target_dest_str_err[IP6ADDR_STRLEN_MAX];
            ip6addr_ntoa_r(&dtn_target_node, target_dest_str_err, sizeof(target_dest_str_err));
            fprintf(stderr, "DTN Controller: Routing OK for %s, but failed to retrieve packet?\n", target_dest_str_err);
            if (retrieved_entry) {
                 fprintf(stderr, "DTN Controller: Retrieved NULL pbuf from storage? Freeing entry struct.\n");
                 dtn_storage_free_retrieved_entry_struct(retrieved_entry);
            }
        }
    }
}