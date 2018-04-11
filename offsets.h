#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/utsname.h>
#define off_kernel_base 0xfffffff007004000 //kernel base
#define off_agx_cmdq_vtable 0xfffffff006ff9330 //AGXCommandQueue vtable
#define off_osdata_metaclass 0xfffffff0074ac4f8 //OSData::getMetaClass
#define off_osserializer_serialize 0xfffffff0074c2fa4 //OSSerializer::Serialize
#define off_kuuid_copy 0xfffffff0074cdf3c //k_uuid_copy
#define off_allproc 0xfffffff007625808 //allproc
#define off_realhost 0xfffffff0075c0b98 //realhost
#define off_call5 0xfffffff006249e90 //call5


//iPhone 6S (iPhone8,2)
#ifdef I_HAVE_AN_IPHONE_8_2_ON_11_2
#define off_kernel_base 0xfffffff007004000 //kernel base
#define off_agx_cmdq_vtable 0xfffffff006ff9330; //AGXCommandQueue vtable
#define off_osdata_metaclass 0xfffffff0074ac4f8; //OSData::getMetaClass
#define off_osserializer_serialize 0xfffffff0074c2fa4; //OSSerializer::Serialize
#define off_kuuid_copy 0xfffffff0074cdf3c; //k_uuid_copy
#define off_allproc 0xfffffff007625808; //allproc
#define off_realhost 0xfffffff0075c0b98; //realhost
#define off_call5 0xfffffff006249e90; //call5
#endif
