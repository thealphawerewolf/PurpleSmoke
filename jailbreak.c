//
//  jailbreak.c
//  jailbreak112
//
//  Created by Sem Voigtländer on 11/04/2018.
//  Copyright © 2018 Jailed Inc. All rights reserved.
//

#include "jailbreak.h"
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
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include "offsets.h"
#include "bazadleak.h"


//Kernel memory helpers
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

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

size_t kread(uint64_t where, void *p, size_t size){
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {

            fprintf(stderr, "[e][%#x] error reading kernel @%p (%s)\n",tfp0,  (void *)(offset + where), mach_error_string(rv));
            break;
        }
        offset += sz;
    }
    return offset;
}
uint64_t kread_uint64(uint64_t where){
    uint64_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

uint32_t kread_uint32(uint64_t where){
    uint32_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

size_t kwrite(uint64_t where, const void *p, size_t size){
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (mach_vm_offset_t)p + offset, (mach_msg_type_number_t)chunk);
        if (rv) {
            //fprintf(stderr, "[e] error writing kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

size_t kwrite_uint64(uint64_t where, uint64_t value){
    return kwrite(where, &value, sizeof(value));
}

size_t kwrite_uint32(uint64_t where, uint32_t value){
    return kwrite(where, &value, sizeof(value));
}



uint64_t kaslr_shift = 0;
uint64_t kernel_text_base = 0;
uint64_t allproc = 0;
uint64_t realhost = 0;
uint64_t osdata_get_metaclass = 0;
uint64_t osserializer_serialize = 0;
uint64_t kernel_return = 0;
uint64_t kernel_uuid_copy = 0;
uint64_t proc_task = 0;
uint64_t portlist[0xfffff];

kern_return_t analyzeport(mach_port_t port)
{
    //Get the type of the port
    mach_port_type_t type = MACH_PORT_TYPE_NONE;
    mach_port_type(mach_task_self(), port, &type);
    kern_return_t err = KERN_FAILURE;
    switch (type) {
        case MACH_PORT_TYPE_NONE:
            err = KERN_FAILURE;
            break;
        case MACH_PORT_TYPE_RECEIVE:
            err = KERN_SUCCESS;
            printf("(send)\n");
            break;
        case MACH_PORT_TYPE_SEND:
            err = KERN_SUCCESS;
            printf("(send)\n");
            break;
        case MACH_PORT_TYPE_SEND_RECEIVE:
            err = KERN_SUCCESS;
            printf("(send/receive)\n");
            break;
        case MACH_PORT_TYPE_PORT_SET:
            err = KERN_SUCCESS;
            printf("(port set)\n");
            break;
        case MACH_PORT_TYPE_DEAD_NAME:
            err = KERN_FAILURE;
            printf("(dead)\n");
            break;
        case MACH_PORT_TYPE_PORT_RIGHTS:
            err = KERN_SUCCESS;
            printf("(port rights)\n");
            break;
        case MACH_PORT_TYPE_PORT_OR_DEAD:
            err = KERN_FAILURE;
            printf("(port/dead)\n");
            break;
            
        default:
            err = KERN_SUCCESS;
            printf("(unknown)\n");
            break;
    }
    return err;
};

struct thread_args {
    uint64_t buf[32];
    exception_port_t exc;
};

void racer(void* arg){
    printf("Through the gates of hell, as we make our way to heaven. Through the nazi lines, primo victoria!\n");
    
    //Eventialy exception handling will be done
    if(arg)
    {
        struct thread_args* args = (struct thread_args*)arg;
        printf("Exception port: %#x\n", args->exc);
    }
    
    //Counter for the number of found ports
    int numFoundPorts = 0;
    
    //Set up the buffer to be used for the kernel object
    char buf[0x2000];
    for(int i = 0; i < 0x2000; i++)
    {
        buf[i] = 'A';
    }
    
    //Set up the address buffer with some random data
    uint address[] = {
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41
    };
    
    //Start bruteforcing the port
    for(int i = ((0 << 16) + 2); i < 0xfffff; i++)
    {

        //Firstly initialize a machport with receive rights
        mach_port_t vcport = MACH_PORT_NULL;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &vcport);
        
        //Give the port sendrights as well
        mach_port_insert_right(mach_task_self(), vcport, vcport, MACH_MSG_TYPE_MAKE_SEND);
        
        //Move the port to the old port and change the allocated port to the bruteforced port value
        int oldport = vcport;
        vcport = i;
        

        //Check if the port is valid by creating a kernel object
        kern_return_t success = mach_port_kernel_object(mach_task_self(), vcport, (uint*)&buf, (uint*)&address);
        
        //We should only continue if our port is valid
        if(success == KERN_SUCCESS)
        {
            //Make sure that we do not print or deallocate out our own task and that the current port is not null
            if(vcport != mach_task_self() && vcport)
            {
                
                printf("found port: %#x ",vcport);
                if(analyzeport(vcport) == KERN_SUCCESS)
                {
                    success = KERN_SUCCESS;
                    
                    if(oldport)
                        mach_port_deallocate(mach_task_self(), oldport);
                }
                portlist[i] = vcport;
                numFoundPorts++;
            }
            if(portlist[i] != 0)
            {
                tfp0 = (mach_port_t)portlist[i];
                uint64_t readval = kread_uint64(kernel_text_base);
                if(readval != 0){ printf("READ: %#llx\n", readval);}
            }
            
            //If we dealloc more than 76 ports our program crashes?
            /*if(numFoundPorts > 76)
            {
                break;
            }*/
        }
    }

    printf("Done finding ports.\n");
}

int jailbreak()
{
    struct utsname kvers = {0};
    uname(&kvers);
    
    //Print out the full kernel version
    printf("%s\n\n",kvers.version);
    
    //Leak the kernelpointer from X18 using bazad's exploit
    uint64_t ptr_leak = x18_leak();
    kernel_text_base = ptr_leak - (0xfffffff01a29925c - 0xfffffff01a204000);
    kaslr_shift = kernel_text_base - off_kernel_base;
    osdata_get_metaclass = off_osdata_metaclass + kaslr_shift;
    kernel_return = osdata_get_metaclass + 8 + kaslr_shift;
    osserializer_serialize = off_osserializer_serialize + kaslr_shift;
    kernel_uuid_copy = off_kuuid_copy + kaslr_shift;
    allproc = off_allproc + kaslr_shift;
    realhost = off_realhost + kaslr_shift;
    proc_task = off_proc_task + kaslr_shift;
    printf("EL0 leak: %#llx\n", ptr_leak);
    printf("kaslr_shift: %#llx\n", kaslr_shift);
    printf("kernel base: %#llx\n", kernel_text_base);
    printf("allproc: %#llx\n", allproc);
    printf("realhost: %#llx\n", realhost);
    printf("osdata_get_metaclass: %#llx\n", osdata_get_metaclass);
    printf("ret: %#llx\n", kernel_return);
    printf("osserialize_serialize: %#llx\n", osserializer_serialize);
    printf("k_uuid_copy: %#llx\n", kernel_uuid_copy);
    printf("proc_task: %#llx\n\n", proc_task);
    printf("we %s tfp0.\n", MACH_PORT_VALID(tfp0) ? "have" : "do not have");

    //Do my very own port race
    pthread_t racerthread;
    pthread_create(&racerthread, NULL, (void*)racer, NULL);
    if(sizeof(portlist) / sizeof(portlist[0]) < 1)
    {
        printf("Failed to find any ports.\n");
    }
    
    printf("All done! Let's hope a kernel exploit is coming soon.\n");
    return ptr_leak != 0;
}
