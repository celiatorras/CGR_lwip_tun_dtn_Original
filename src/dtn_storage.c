#include "dtn_storage.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/ip6_addr.h"

Storage_Function* dtn_storage_create(DTN_Module* parent) {
    Storage_Function* storage = (Storage_Function*)malloc(sizeof(Storage_Function));
    if (storage) {
        storage->parent_module = parent;
        storage->stored_packets_count = 0;
        storage->max_storage_bytes = 1024 * 1024; // 1MB limit
        storage->packet_list_head = NULL;
        printf("DTN Storage Function created (Max: %zu bytes, Max Packets: %d).\n", storage->max_storage_bytes, MAX_STORED_PACKETS);
    } else {
        perror("Failed to allocate memory for Storage_Function");
    }
    return storage;
}

void dtn_storage_destroy(Storage_Function* storage) {
    if (!storage) return;
    printf("Destroying DTN Storage Function...\n");

    Stored_Packet_Entry* current = storage->packet_list_head;
    Stored_Packet_Entry* next_entry;
    while (current != NULL) {
        next_entry = current->next;
        char addr_str[IP6ADDR_STRLEN_MAX];
        ip6addr_ntoa_r(&current->original_dest, addr_str, sizeof(addr_str));
        printf("DTN Storage: Freeing stored pbuf (original dest: %s) during destroy.\n", addr_str);
        pbuf_free(current->p); 
        free(current);         
        current = next_entry;
    }
    storage->packet_list_head = NULL;
    storage->stored_packets_count = 0;

    free(storage);
}

int dtn_storage_is_full(Storage_Function* storage) {
    if (!storage) return 1;
    return storage->stored_packets_count >= MAX_STORED_PACKETS;
}

int dtn_storage_store_packet(Storage_Function* storage, struct pbuf* p, const ip6_addr_t* original_dest) {
    if (!storage || !p || !original_dest) {
        fprintf(stderr, "DTN Storage: Invalid arguments to store_packet.\n");
        return 0;
    }

    if (dtn_storage_is_full(storage)) {
        char addr_str[IP6ADDR_STRLEN_MAX];
        ip6addr_ntoa_r(original_dest, addr_str, sizeof(addr_str));
        printf("DTN Storage: Storage is full. Cannot store packet for %s.\n", addr_str);
        return 0;
    }

    Stored_Packet_Entry* new_entry = (Stored_Packet_Entry*)malloc(sizeof(Stored_Packet_Entry));
    if (!new_entry) {
        perror("DTN Storage: Failed to allocate memory for Stored_Packet_Entry");
        return 0;
    }

    pbuf_ref(p);
    new_entry->p = p;
    memcpy(&new_entry->original_dest, original_dest, sizeof(ip6_addr_t));
    new_entry->stored_time_ms = sys_now();
    new_entry->next = NULL;

    if (storage->packet_list_head == NULL) {
        storage->packet_list_head = new_entry;
    } else {
        Stored_Packet_Entry* current_item = storage->packet_list_head;
        while (current_item->next != NULL) {
            current_item = current_item->next;
        }
        current_item->next = new_entry;
    }

    storage->stored_packets_count++;
    char addr_str_log[IP6ADDR_STRLEN_MAX];
    ip6addr_ntoa_r(original_dest, addr_str_log, sizeof(addr_str_log));
    printf("DTN Storage: Packet for %s stored successfully at time %u. Total stored: %zu\n",
           addr_str_log, new_entry->stored_time_ms, storage->stored_packets_count);

    return 1;
}


Stored_Packet_Entry* dtn_storage_retrieve_packet_for_dest(Storage_Function* storage, const ip6_addr_t* target_dest) {
    if (!storage || !target_dest || storage->packet_list_head == NULL) {
        return NULL;
    }

    Stored_Packet_Entry* current = storage->packet_list_head;
    Stored_Packet_Entry* prev = NULL;
    Stored_Packet_Entry* match = NULL;
    Stored_Packet_Entry* prev_for_match = NULL;

    current = storage->packet_list_head;
    prev = NULL;
    while(current != NULL) {
        ip6_addr_t current_dest_nozone;
        ip6_addr_t target_dest_nozone;

        memcpy(&current_dest_nozone, &current->original_dest, sizeof(ip6_addr_t));
        memcpy(&target_dest_nozone, target_dest, sizeof(ip6_addr_t));

#if LWIP_IPV6_SCOPES
        ip6_addr_set_zone(&current_dest_nozone, IP6_NO_ZONE);
        ip6_addr_set_zone(&target_dest_nozone, IP6_NO_ZONE);
#endif

        if (ip6_addr_cmp(&current_dest_nozone, &target_dest_nozone)) {
            match = current;
            prev_for_match = prev;
            break; 
        }
        prev = current;
        current = current->next;
    }

    if (match) {
        if (prev_for_match == NULL) {
            storage->packet_list_head = match->next;
        } else {
            prev_for_match->next = match->next;
        }
        storage->stored_packets_count--;
        char addr_str[IP6ADDR_STRLEN_MAX];
        ip6addr_ntoa_r(&match->original_dest, addr_str, sizeof(addr_str));
        printf("DTN Storage: Retrieving packet for %s (stored at %u). Total stored now: %zu\n",
               addr_str, match->stored_time_ms, storage->stored_packets_count);
        match->next = NULL;
        return match;
    }
    return NULL;
}

void dtn_storage_free_retrieved_entry_struct(Stored_Packet_Entry* entry) {
    if (entry) {
        char addr_str[IP6ADDR_STRLEN_MAX];
        ip6addr_ntoa_r(&entry->original_dest, addr_str, sizeof(addr_str));
        printf("DTN Storage: Freeing Stored_Packet_Entry structure for %s (pbuf management is caller's responsibility).\n", addr_str);
        free(entry);
    }
}