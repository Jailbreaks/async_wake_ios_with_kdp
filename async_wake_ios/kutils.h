#ifndef kutils_h
#define kutils_h

#include <mach/mach.h>

uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_kernel_base(void);

uint64_t current_thread(void);
uint64_t thread_get_debug_area(mach_port_t thread_port);

mach_port_t fake_host_priv(void);

#endif /* kutils_h */
