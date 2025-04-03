// Standard and system headers for I/O, network interfaces, and TUN/TAP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>

// lwIP headers for initializing stack, IP, and buffer handling
#include "lwip/init.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/timeouts.h"
#include "lwip/pbuf.h"
#include "lwip/ip4.h"
#include "lwip/prot/ip4.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/icmp6.h"

// Constants
#define TUN_IFNAME "tun0"
#define DEFAULT_TTL 64

/**
 * Allocate and configure a TUN interface.
 * Returns a file descriptor on success, -1 on failure.
 */
int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR); // Open TUN device
    if (fd < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN mode, no packet info
    strncpy(ifr.ifr_name, dev, IFNAMSIZ); // Set desired device name

    // Configure TUN device
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }

    strcpy(dev, ifr.ifr_name); // Update dev with actual name
    return fd;
}

/**
 * Send data from lwIP to the TUN device.
 */
err_t tunif_output(struct netif *netif, struct pbuf *p) {
    int tun_fd = *(int *)netif->state;

    // Allocate buffer to hold the full packet
    void *buffer = malloc(p->tot_len);
    if (!buffer) return ERR_MEM;
    
    pbuf_copy_partial(p, buffer, p->tot_len, 0);
    printf("Sending packet of %d bytes via tun\n", p->tot_len);
    
    // Write to the TUN interface
    ssize_t written = write(tun_fd, buffer, p->tot_len);
    free(buffer);
    
    if (written < 0) {
        perror("TUN write failed");
        return ERR_IF;
    }
    
    if ((size_t)written != p->tot_len) {
        fprintf(stderr, "TUN write short: %zd vs %d\n", written, p->tot_len);
        return ERR_IF;
    }
    
    return ERR_OK;
}

/**
 * Read data from the TUN device and feed it into the lwIP stack.
 * This is called when data is ready to be read from the TUN fd.
 */
err_t tunif_input(struct netif *netif) {
    int tun_fd = *(int *)netif->state;
    char buf[1600]; // Buffer for incoming packet

    int len = read(tun_fd, buf, sizeof(buf));
    if (len <= 0) return ERR_OK;
    
    struct pbuf *p = pbuf_alloc(PBUF_IP, len, PBUF_POOL);
    if (!p) return ERR_MEM;
    
    pbuf_take(p, buf, len);
    
    // Determine IP version and dispatch to proper handler
    u8_t ip_version = ((u8_t *)p->payload)[0] >> 4;
    if (ip_version == 6) {
        ip6_input(p, netif);
    } else if (ip_version == 4) {
        ip_input(p, netif);
    } else {
        pbuf_free(p);
    }    
    
    printf("Got packet of %d bytes\n", len);
    return ERR_OK;
}

/**
 * IPv4 output wrapper function used by lwIP to send packets to tunif_output.
 */
err_t tunif_ip4_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    return netif->linkoutput(netif, p);
}

/**
 * IPv6 output wrapper function used by lwIP to send packets to tunif_output.
 */
err_t tunif_ip6_output(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
    return netif->linkoutput(netif, p);
}

/**
 * Initialize the virtual TUN interface within lwIP.
 * Sets up output functions and interface parameters.
 */
err_t tunif_init(struct netif *netif) {
    netif->name[0] = 't';
    netif->name[1] = 'n';
    netif->output = tunif_ip4_output; 
    netif->output_ip6 = tunif_ip6_output;
    netif->linkoutput = tunif_output;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST;
    return ERR_OK;
}

/**
 * Main entry point. Initializes lwIP, sets up the TUN interface,
 * assigns IP addresses, and enters main I/O loop.
 */
int main() {
    lwip_init(); // Initialize lwIP stack
    
    struct netif tun_netif;
    ip4_addr_t ipaddr, netmask, gw;

    // Set IPv4 parameters
    IP4_ADDR(&ipaddr, 10, 0, 0, 2);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 10, 0, 0, 1);
    
    // Allocate and configure the TUN interface
    char tun_name[IFNAMSIZ] = TUN_IFNAME;
    int tun_fd = tun_alloc(tun_name);
    if (tun_fd < 0) {
        fprintf(stderr, "TUN device allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    // Add interface to lwIP and bring it up
    netif_add(&tun_netif, &ipaddr, &netmask, &gw, &tun_fd, tunif_init, ip_input);
    netif_set_default(&tun_netif);
    netif_set_up(&tun_netif);

     // Set IPv6 global and link-local addresses
    ip6_addr_t ip6addr;
    ip6addr_aton("fd00::2", &ip6addr); 
    netif_add_ip6_address(&tun_netif, &ip6addr, NULL);
    netif_create_ip6_linklocal_address(&tun_netif, 1);  
    netif_ip6_addr_set_state(&tun_netif, 0, IP6_ADDR_VALID);

    printf("lwIP stack started. Interface %s is up.\n", tun_name);
    
    // Main loop: poll TUN fd and lwIP timeouts
    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        
        struct timeval tv = {1, 0};  // 1-second timeout for select
        int ret = select(tun_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (ret > 0 && FD_ISSET(tun_fd, &readfds)) {
            tunif_input(&tun_netif); // Process incoming packet
        }
        
        sys_check_timeouts(); // Handle lwIP time-based events
    }
    
    return 0;
}