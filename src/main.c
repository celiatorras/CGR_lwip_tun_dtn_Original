#include <stdio.h>
#include <stdlib.h>
#include <string.h>     
#include <fcntl.h>     
#include <unistd.h>     
#include <sys/ioctl.h> 
#include <linux/if.h>  
#include <linux/if_tun.h>
#include <errno.h>     
#include <sys/select.h> 
#include <sys/time.h>  
#include <stdbool.h>    

// LwIP headers
#include "lwip/init.h"      
#include "lwip/netif.h"     
#include "lwip/pbuf.h"     
#include "lwip/timeouts.h"  
#include "lwip/ip6.h"     
#include "lwip/ip6_addr.h"  
#include "lwip/ip.h"       
#include "lwip/sys.h"    
#include "lwip/err.h"      

// DTN Module headers
#include "dtn_module.h"
#include "dtn_controller.h" 
#include "dtn_routing.h"    

// Constants
#define TUN_IFNAME "tun0"
#define PACKET_BUF_SIZE 2048

static DTN_Module* global_dtn_module = NULL;

int tun_alloc(char *dev_name, int max_len);
err_t tunif_output(struct netif *netif, struct pbuf *p);
err_t tunif_input(struct netif *netif);
err_t tunif_ip6_output(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr);
err_t tunif_init(struct netif *netif);

int tun_alloc(char *dev_name, int max_len) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("Opening /dev/net/tun"); return fd; }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (dev_name && *dev_name) { strncpy(ifr.ifr_name, dev_name, IFNAMSIZ); ifr.ifr_name[IFNAMSIZ - 1] = '\0'; }
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) { perror("ioctl(TUNSETIFF)"); close(fd); return -1; }
    strncpy(dev_name, ifr.ifr_name, max_len); dev_name[max_len - 1] = '\0';
    return fd;
}

err_t tunif_output(struct netif *netif, struct pbuf *p) {
    if (!netif || !netif->state || !p) { return ERR_ARG; }
    int tun_fd = *(int *)netif->state; 
    char buffer[PACKET_BUF_SIZE];
    if (p->tot_len > sizeof(buffer)) { fprintf(stderr, "Packet too large for output buffer (%d vs %ld)\n", p->tot_len, sizeof(buffer)); return ERR_MEM; }

    if (pbuf_copy_partial(p, buffer, p->tot_len, 0) != p->tot_len) {
        fprintf(stderr, "pbuf_copy_partial failed to copy full packet\n");
        return ERR_BUF;
    }

    ssize_t written = write(tun_fd, buffer, p->tot_len);
    if (written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) { return ERR_WOULDBLOCK; }
        perror("TUN write failed"); return ERR_IF;
    }
    if ((size_t)written != p->tot_len) { fprintf(stderr, "TUN write short: wrote %zd vs %d\n", written, p->tot_len); return ERR_IF; }
    return ERR_OK;
}

err_t tunif_input(struct netif *netif) {
     if (!netif || !netif->state) { return ERR_ARG; }
     if (!global_dtn_module || !global_dtn_module->controller) {
         fprintf(stderr, "tunif_input: DTN Module or Controller not initialized!\n");
         char discard_buf[100];
         read(*(int *)netif->state, discard_buf, sizeof(discard_buf));
         return ERR_IF;
     }

     int tun_fd = *(int *)netif->state;
     char buf[PACKET_BUF_SIZE];
     ssize_t len = read(tun_fd, buf, sizeof(buf));

     if (len < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) { return ERR_OK; } perror("TUN read error"); return ERR_IF; }
     if (len == 0) { printf("TUN read 0 bytes, tunnel closed by peer?\n"); return ERR_CONN; }

     struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
     if (!p) { fprintf(stderr, "Failed to allocate pbuf for incoming packet of size %zd\n", len); return ERR_MEM; }

     err_t copy_err = pbuf_take(p, buf, len);
     if (copy_err != ERR_OK) { fprintf(stderr, "Failed to copy buffer to pbuf (%d)\n", copy_err); pbuf_free(p); return copy_err; }

     dtn_controller_process_incoming(global_dtn_module->controller, p, netif);
     return ERR_OK;
}

err_t tunif_ip6_output(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
    LWIP_UNUSED_ARG(ipaddr);
    return netif->linkoutput(netif, p);
}

err_t tunif_init(struct netif *netif) {
    if (!netif) { return ERR_ARG; }
    netif->name[0] = 't'; netif->name[1] = 'n';
    netif->output_ip6 = tunif_ip6_output;
    netif->linkoutput = tunif_output;
    netif->input = ip6_input;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}


int main() {
    lwip_init();

    global_dtn_module = dtn_module_init(); 
    if (!global_dtn_module) {
         fprintf(stderr, "Failed to initialize DTN Module\n");
         exit(EXIT_FAILURE);
    }

    struct netif tun_netif; 
    memset(&tun_netif, 0, sizeof(tun_netif));

    char tun_name[IFNAMSIZ]; 
    strncpy(tun_name, TUN_IFNAME, IFNAMSIZ -1); 
    tun_name[IFNAMSIZ - 1] = '\0';

    int tun_fd = tun_alloc(tun_name, sizeof(tun_name)); 
    if (tun_fd < 0) {
        fprintf(stderr, "TUN device allocation failed\n");
        dtn_module_cleanup(global_dtn_module);
        exit(EXIT_FAILURE);
    }
    printf("TUN device '%s' created successfully (fd: %d).\n", tun_name, tun_fd);

    int flags = fcntl(tun_fd, F_GETFL, 0);
    if (flags == -1) { perror("fcntl F_GETFL"); close(tun_fd); dtn_module_cleanup(global_dtn_module); exit(EXIT_FAILURE); }
    if (fcntl(tun_fd, F_SETFL, flags | O_NONBLOCK) == -1) { perror("fcntl F_SETFL O_NONBLOCK"); close(tun_fd); dtn_module_cleanup(global_dtn_module); exit(EXIT_FAILURE); }

    if (!netif_add(&tun_netif, (void*)&tun_fd, tunif_init, ip6_input)) {
         fprintf(stderr, "Failed to add netif to lwIP\n");
         close(tun_fd);
         dtn_module_cleanup(global_dtn_module);
         exit(EXIT_FAILURE);
    }

    netif_set_default(&tun_netif);
    netif_set_up(&tun_netif);
    printf("Interface set UP.\n");

    ip6_addr_t ip6addr_lwip_stack;
    if (!ip6addr_aton("fd00::2", &ip6addr_lwip_stack)) {
        fprintf(stderr, "Failed to parse LwIP stack IPv6 address\n");
        netif_remove(&tun_netif); close(tun_fd); dtn_module_cleanup(global_dtn_module);
        exit(EXIT_FAILURE);
    }
    if (!netif_add_ip6_address(&tun_netif, &ip6addr_lwip_stack, NULL)) {
        fprintf(stderr, "Failed to add LwIP stack address fd00::2 to netif.\n");
    } else {
        printf("LwIP stack address fd00::2 add attempted.\n");
    }

    netif_create_ip6_linklocal_address(&tun_netif, 1);
    printf("Link-local address creation requested.\n");

    #if LWIP_IPV6_NUM_ADDRESSES > 0
        s8_t addr_index = netif_get_ip6_addr_match(&tun_netif, &ip6addr_lwip_stack);
        if (addr_index >= 0 && netif_ip6_addr_state(&tun_netif, addr_index) != IP6_ADDR_INVALID) {
            netif_ip6_addr_set_state(&tun_netif, addr_index, IP6_ADDR_PREFERRED);
            printf("State for address fd00::2 (index %d) set to PREFERRED.\n", addr_index);
        } else {
             if (netif_ip6_addr_state(&tun_netif, 0) != IP6_ADDR_INVALID) {
                netif_ip6_addr_set_state(&tun_netif, 0, IP6_ADDR_PREFERRED);
                printf("State for address at index 0 set to PREFERRED (fallback).\n");
            }
        }
    #endif

    printf("Waiting for addresses to settle...\n");
    sleep(2);

    printf("LwIP stack started. Interface %s (LwIP: %c%c) is up and configured.\n",
           tun_name, tun_netif.name[0], tun_netif.name[1]);

    printf("Entering main loop...\n");

    u32_t contact_simulation_start_time_ms = sys_now();
    bool contact_made_available = false;
    #define CONTACT_CHECK_INTERVAL_MS 1000
    #define SIMULATE_CONTACT_AFTER_MS 15000


    while (1) {
        fd_set readfds; 
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);

        struct timeval tv; 
        u32_t lwip_timeout_ms = sys_timeouts_sleeptime();

        u32_t app_timeout_ms = CONTACT_CHECK_INTERVAL_MS;
        if (lwip_timeout_ms != SYS_TIMEOUTS_SLEEPTIME_INFINITE && lwip_timeout_ms < app_timeout_ms) {
            app_timeout_ms = lwip_timeout_ms;
        }

        tv.tv_sec = app_timeout_ms / 1000;
        tv.tv_usec = (app_timeout_ms % 1000) * 1000;

        int ret = select(tun_fd + 1, &readfds, NULL, NULL, &tv);

        if (ret < 0) { if (errno == EINTR) { continue; } perror("select error"); break; }

        sys_check_timeouts();

        if (FD_ISSET(tun_fd, &readfds)) {
            if (tunif_input(&tun_netif) == ERR_CONN) { fprintf(stderr, "TUN connection closed. Exiting.\n"); break; }
        }

        u32_t current_time_ms = sys_now();

        if (!contact_made_available && (current_time_ms - contact_simulation_start_time_ms > SIMULATE_CONTACT_AFTER_MS)) {
            if (global_dtn_module && global_dtn_module->routing) {
                dtn_routing_set_contact_availability(global_dtn_module->routing, true);
                contact_made_available = true;
            }
        }

        if (global_dtn_module && global_dtn_module->controller) {
             dtn_controller_attempt_forward_stored(global_dtn_module->controller, &tun_netif);
        }
    }

    printf("Shutting down...\n");
    if (global_dtn_module && global_dtn_module->routing && contact_made_available) {
        dtn_routing_set_contact_availability(global_dtn_module->routing, false);
    }
    netif_set_down(&tun_netif);
    netif_remove(&tun_netif);
    close(tun_fd); 
    dtn_module_cleanup(global_dtn_module); 

    printf("Shutdown complete.\n");
    return 0;
}
