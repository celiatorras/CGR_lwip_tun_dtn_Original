// dtn_storage.h
#ifndef DTN_STORAGE_H
#define DTN_STORAGE_H

#include <stddef.h>
#include "dtn_module.h"
#include "lwip/pbuf.h"
#include "lwip/ip6_addr.h"
#include <stdbool.h> 

#define MAX_STORED_PACKETS 5 

typedef struct Stored_Packet_Entry {
    struct pbuf *p;
    ip6_addr_t original_dest;
    u32_t stored_time_ms;
    struct Stored_Packet_Entry *next;
} Stored_Packet_Entry;

typedef struct Storage_Function {
    DTN_Module* parent_module;
    size_t stored_packets_count;
    size_t max_storage_bytes;
    Stored_Packet_Entry* packet_list_head;
} Storage_Function;


Storage_Function* dtn_storage_create(DTN_Module* parent);
void dtn_storage_destroy(Storage_Function* storage);
int dtn_storage_store_packet(Storage_Function* storage, struct pbuf* p, const ip6_addr_t* original_dest);
int dtn_storage_is_full(Storage_Function* storage);
Stored_Packet_Entry* dtn_storage_retrieve_packet_for_dest(Storage_Function* storage, const ip6_addr_t* target_dest);

/**
 * @brief Frees a Stored_Packet_Entry structure ONLY.
 * The caller is responsible for managing the pbuf (p) within the entry.
 *
 * @param entry The Stored_Packet_Entry structure to free.
 */
void dtn_storage_free_retrieved_entry_struct(Stored_Packet_Entry* entry); // Renamed

#endif // DTN_STORAGE_H