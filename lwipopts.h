#ifndef LWIPOPTS_H
#define LWIPOPTS_H

// ------------------------------
// Core System Configuration
// ------------------------------

#define NO_SYS 1                         // No OS abstraction layer; using raw API (no threads, semaphores, etc.)
#define LWIP_TIMERS 1                    // Enable built-in timer support (used for things like TCP timeouts)
#define LWIP_TIMEVAL_PRIVATE 0           // Use system <sys/time.h>'s timeval instead of lwIP's private definition
#define SYS_LIGHTWEIGHT_PROT 1           // Enable lightweight protection (for disabling/enabling interrupts on critical sections)

// ------------------------------
// Protocol Support Configuration
// ------------------------------

#define LWIP_STATS 0                     // Disable statistics (saves memory, disable if not debugging)
#define LWIP_ARP 0                       // Disable ARP, since we're not using Ethernet (TUN is L3)
#define LWIP_ETHERNET 0                  // Disable Ethernet support entirely
#define LWIP_IPV4 1                      // Enable IPv4 support
#define LWIP_TCP 1                       // Enable TCP protocol support
#define LWIP_UDP 1                       // Enable UDP protocol support
#define LWIP_ICMP 1                      // Enable ICMP for IPv4 (e.g., ping)

// ------------------------------
// IPv6 Configuration
// ------------------------------

#define LWIP_IPV6 1                     // Enable IPv6 support
#define LWIP_ICMP6 1                    // Enable ICMPv6 (neighbor discovery, ping, etc.)
#define LWIP_IPV6_REASS 0               // Disable IPv6 packet reassembly (can save RAM)
#define LWIP_ND6_QUEUEING 0             // Disable queuing of packets waiting for ND6 resolution
#define LWIP_NETIF_IPV6_ADDR_GEN_AUTO 1 // Automatically generate IPv6 addresses (e.g., link-local)

// ------------------------------
// Memory Configuration
// ------------------------------

#define MEM_SIZE 1600                   // Heap size for lwIP internal memory (used for dynamic memory)
#define MEMP_NUM_PBUF 16                // Number of internal pbuf memory chunks
#define PBUF_POOL_SIZE 16               // Number of pbufs in the pool
#define PBUF_POOL_BUFSIZE 512           // Size of each pbuf buffer in the pool

// ------------------------------
// Network Interface Callbacks
// ------------------------------

#define LWIP_NETIF_LINK_CALLBACK 1     // Enable link status change callback support
#define LWIP_NETIF_STATUS_CALLBACK 1   // Enable network interface status change callback support

// ------------------------------
// API Support
// ------------------------------

#define LWIP_SOCKET 0                  // Disable BSD-style socket API (not needed in NO_SYS mode)
#define LWIP_NETCONN 0                 // Disable Netconn API (threaded, used with RTOS)

// ------------------------------
// Debugging (Optional - Uncomment to enable)
// ------------------------------

// #define ICMP_DEBUG LWIP_DBG_ON
// #define LWIP_DEBUG 1
// #define LWIP_DBG_MIN_LEVEL LWIP_DBG_LEVEL_ALL
// #define IP_DEBUG LWIP_DBG_ON
// #define ICMP6_DEBUG LWIP_DBG_ON
// #define IP6_DEBUG LWIP_DBG_ON
// #define LWIP_DBG_MIN_LEVEL LWIP_DBG_LEVEL_WARNING

#endif
