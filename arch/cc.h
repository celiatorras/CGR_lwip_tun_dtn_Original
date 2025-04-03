#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

// Standard C headers needed for platform macros and types
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ------------------------------
// Protection Macros (No-OS / Raw Mode)
// ------------------------------

typedef unsigned int sys_prot_t;  // Dummy type for critical section protection (unused in NO_SYS mode)

// Declare a protection variable (no-op here)
#define SYS_ARCH_DECL_PROTECT(x) sys_prot_t x

// Enter critical section (no-op)
#define SYS_ARCH_PROTECT(x)      (void)(x)

// Exit critical section (no-op)
#define SYS_ARCH_UNPROTECT(x)    (void)(x)

// Since here running in NO_SYS (no threading), don't need real protection.
// These are stubs so lwIP compiles cleanly.

// ------------------------------
// Structure Packing Macros
// ------------------------------

// Used to ensure byte-accurate structure layout (important for protocols)

#define PACK_STRUCT_BEGIN                     // No-op for GCC
#define PACK_STRUCT_STRUCT __attribute__((__packed__))  // Tells GCC to pack the struct
#define PACK_STRUCT_END                       // No-op
#define PACK_STRUCT_FIELD(x) x                // Field macro, not needed to modify on GCC

// ------------------------------
// Diagnostic and Assertion Macros
// ------------------------------

// Print debug messages
#define LWIP_PLATFORM_DIAG(x) do {printf x;} while(0)

// Assert and abort program on failure
#define LWIP_PLATFORM_ASSERT(x) \
  do { printf("Assert failed: %s\n", x); abort(); } while(0)

// These macros let lwIP use printf/assert-style debugging
// without assuming a particular platform API (like syslog or RTOS loggers)

#endif /* LWIP_ARCH_CC_H */
