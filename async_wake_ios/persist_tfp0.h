#ifndef persist_tfp0_h
#define persist_tfp0_h

#include <mach/mach_port.h>

void persist_port(mach_port_t port);
mach_port_t try_restore_port();

#endif
