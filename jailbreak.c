size_t
kread(uint64_t where, void *p, size_t size)
{
    
    if(tfp0 == MACH_PORT_NULL) {
        printf("[ERROR]: tfp0's port is null!\n");
    }

    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);

        if (rv || sz == 0) {
            printf("[ERROR]: error reading buffer at @%p\n", (void *)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

uint64_t
kread_uint64(uint64_t where)
{
    uint64_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

uint32_t
kread_uint32(uint64_t where)
{
    uint32_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

size_t
kwrite(uint64_t where, const void *p, size_t size)
{
    
    if(tfp0 == MACH_PORT_NULL) {
        printf("[ERROR]: tfp0's port is null!\n");
    }
    
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (mach_vm_offset_t)p + offset, (mach_msg_type_number_t)chunk);
        if (rv) {
            printf("[ERROR]: error copying buffer into region: @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

size_t
kwrite_uint64(uint64_t where, uint64_t value)
{
    return kwrite(where, &value, sizeof(value));
}

size_t
kwrite_uint32(uint64_t where, uint32_t value)
{
    return kwrite(where, &value, sizeof(value));
}
