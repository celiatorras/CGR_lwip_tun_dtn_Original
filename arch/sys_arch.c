#include "lwip/sys.h"
#include <sys/time.h>

/**
 * Return the current system time in milliseconds.
 * This function is required by lwIP for timeouts and timers.
 *
 * It uses gettimeofday() to get the current time and converts it to milliseconds.
 */
u32_t sys_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (u32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

/**
 * Initialize the system architecture layer.
 * Required by lwIP, but in NO_SYS mode this is a no-op.
 */
void sys_init(void) {
}
