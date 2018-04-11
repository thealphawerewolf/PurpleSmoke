#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_port.h>
#include <mach/mach_time.h>
#include <mach/mach_traps.h>
#include <mach/mach_voucher_types.h>
#include <mach/port.h>
//#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include "offsets.h"
#include "bazadleak.h"


//Kernel memory helpers
kern_return_t mach_vm_read
(
 vm_map_t target_task,
 mach_vm_address_t address,
 mach_vm_size_t size,
 vm_offset_t *data,
 mach_msg_type_number_t *dataCnt
 );

kern_return_t mach_vm_write
(
 vm_map_t target_task,
 mach_vm_address_t address,
 vm_offset_t data,
 mach_msg_type_number_t dataCnt
 );

kern_return_t mach_vm_deallocate
(
 vm_map_t target,
 mach_vm_address_t address,
 mach_vm_size_t size
 );

kern_return_t mach_vm_allocate
(
 vm_map_t target,
 mach_vm_address_t *address,
 mach_vm_size_t size,
 int flags
 );

kern_return_t mach_vm_deallocate
(
 vm_map_t target,
 mach_vm_address_t address,
 mach_vm_size_t size
 );

mach_port_t tfp0 = MACH_PORT_NULL;
uint64_t kaslr_shift = 0;
uint64_t kernel_base = 0;
uint64_t allproc = 0;
uint64_t realhost = 0;
uint64_t osdata_get_metaclass = 0;
uint64_t osserializer_serialize = 0;
uint64_t kernel_return = 0;
uint64_t kernel_uuid_copy = 0;

int jailbreak()
{
  struct utsname kvers = {0};
  uname(&kvers);
  
  //Print out the full kernel version
  printf("%s\n",kvers.version);
  
  //Leak the kernelpointer from X18 using bazad's exploit
  uint64_t ptr_leak = x18_leak();
  kernel_base = ptr_leak - 0x95000;
  kaslr_shift = kernel_base - off_kernel_base;
  osdata_get_metaclass = off_osdata_metaclass + kaslr_shift;
  kernel_return = osdata_get_metaclass + 8 + kaslr_shift;
  osserializer_serialize = off_osserializer_serialize + kaslr_shift;
  kernel_uuid_copy = off_kuuid_copy + kaslr_shift;
  allproc = off_allproc + kaslr_shift;
  printf("First we leaked this pointer: %#llx\n", ptr_leak);
  printf("kaslr_shift: %#llx\n", kaslr_shift);
  printf("kernel base: %#llx\n", kernel_base);
  printf("allproc: %#llx\n", allproc);
  printf("realhost: %#llx\n", realhost);
  printf("osdata_get_metaclass: %#llx\n", osdata_get_metaclass);
  printf("ret: %#llx\n", kernel_return);
  printf("osserialize_serialize: %#llx\n", osserializer_serialize);
  printf("k_uuid_copy: %#llx\n", kernel_uuid_copy);
  printf("All done! Let's hope a kernel exploit is coming soon.\n");
  return ptr_leak != 0;
}



