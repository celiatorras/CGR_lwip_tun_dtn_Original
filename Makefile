# ------------------------------
# Compiler and Flags
# ------------------------------

CC = gcc                       # Use GCC as the compiler

CFLAGS = -Wall \              # Enable all compiler warnings
         -DNO_SYS=1 \         # NO_SYS mode (no OS)
         -DLWIP_DEBUG=1 \     # Enable lwIP debug output
         -DLWIP_DBG_MIN_LEVEL=LWIP_DBG_LEVEL_ALL \   # Show all debug messages
         -DICMP6_DEBUG=LWIP_DBG_ON \                 # Enable ICMPv6 debug
         -DIP6_DEBUG=LWIP_DBG_ON \                   # Enable IPv6 debug
         -I./ \               # Include current directory
         -I./arch \           # Include platform-specific headers (e.g., cc.h, sys_arch.c)
         -Ilwip/include \     # lwIP public headers
         -Ilwip/src/include   # lwIP internal source headers

# ------------------------------
# lwIP Source Files
# ------------------------------

LWIP_SRC = \
	lwip/src/core/mem.c \                  
	lwip/src/core/pbuf.c \                 
	lwip/src/core/timeouts.c \            
	lwip/src/core/ipv4/ip4.c \            
	lwip/src/core/ipv4/ip4_addr.c \       
	lwip/src/core/ipv4/ip4_frag.c \      
	lwip/src/core/ipv4/etharp.c \         
	lwip/src/core/stats.c \              
	lwip/src/core/def.c \               
	lwip/src/core/sys.c \   
	lwip/src/core/netif.c \        
	lwip/src/core/inet_chksum.c \     
	lwip/src/core/ipv4/icmp.c \      
	lwip/src/core/udp.c \       
	lwip/src/core/tcp.c \       
	lwip/src/core/tcp_in.c \     
	lwip/src/core/tcp_out.c \      
	lwip/src/netif/ethernet.c \         
	lwip/src/core/ip.c \            
	lwip/src/core/memp.c \       
	lwip/src/api/err.c \          
	lwip/src/core/init.c \            
	lwip/src/core/ipv6/ip6.c \      
	lwip/src/core/ipv6/icmp6.c \   
	lwip/src/core/ipv6/ip6_addr.c \  
	lwip/src/core/ipv6/inet6.c \       
	lwip/src/core/ipv6/nd6.c \           
	lwip/src/core/ipv6/ip6_frag.c \       
	lwip/src/core/ipv6/mld6.c             

# ------------------------------
# Project Sources
# ------------------------------

SOURCES = main.c arch/sys_arch.c $(LWIP_SRC)   # All source files
OBJECTS = $(SOURCES:.c=.o)                     # Object files
TARGET = lwip_tun                              # Output binary name

# ------------------------------
# Build Rules
# ------------------------------

all: $(TARGET)                    # Default make target

# Link all object files into the final binary
$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile each .c file to a .o file
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# ------------------------------
# Clean Rule
# ------------------------------

clean:                            # Delete all build artifacts
	rm -f $(OBJECTS) $(TARGET)
