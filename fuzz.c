#include <hypervisor.h>
#include <netfront.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define uint32_t unsigned long

typedef void (*hc1_t)(uint32_t);
typedef void (*hc2_t)(uint32_t, uint32_t);
typedef void (*hc3_t)(uint32_t, uint32_t, uint32_t);
typedef void (*hc4_t)(uint32_t, uint32_t, uint32_t, uint32_t);
typedef void (*hc5_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

uint32_t getarg(void);


/*
 * Hypercalls with 1 argument
 */
hc1_t hc1[] = {
    (hc1_t) HYPERVISOR_set_trap_table,
    (hc1_t) HYPERVISOR_fpu_taskswitch,
    (hc1_t) HYPERVISOR_get_debugreg,
    (hc1_t) HYPERVISOR_physdev_op,
    (hc1_t) HYPERVISOR_sysctl,
    (hc1_t) HYPERVISOR_domctl,
};

void hc1_fuzzer(void) {
    int i;
    uint32_t args[1];

    for (i = 0; i < sizeof(hc1)/sizeof(*hc1); i++) {
        args[0] = getarg();

        printf("hc1: %i: %x\n", i, args[0]);

        hc1[i](args[0]);
    }
}


/*
 * Hypercalls with 2 arguments
 */
hc2_t hc2[] = {
    (hc2_t) HYPERVISOR_set_gdt,
    (hc2_t) HYPERVISOR_stack_switch,
    (hc2_t) HYPERVISOR_sched_op,
    (hc2_t) HYPERVISOR_set_timer_op,
    (hc2_t) HYPERVISOR_memory_op,
    //(hc2_t) HYPERVISOR_multicall,
    (hc2_t) HYPERVISOR_event_channel_op,
    (hc2_t) HYPERVISOR_xen_version,
    (hc2_t) HYPERVISOR_vm_assist,
    (hc2_t) HYPERVISOR_nmi_op,
};

void hc2_fuzzer(void) {
    int i;
    uint32_t args[2];

    for (i = 0; i < sizeof(hc2)/sizeof(*hc2); i++) {
        args[0] = getarg();
        args[1] = getarg();

        printf("hc2: %i: %x %x\n", i, args[0], args[1]);

        hc2[i](args[0], args[1]);
    }
}


/*
 * Hypercalls with 3 arguments
 */
hc3_t hc3[] = {
    (hc3_t) HYPERVISOR_console_io,
    (hc3_t) HYPERVISOR_grant_table_op,
    (hc3_t) HYPERVISOR_vcpu_op,
    //(hc3_t) HYPERVISOR_suspend,
};

void hc3_fuzzer(void) {
    int i, j;
    uint32_t args[3];

    for (i = 0; i < sizeof(hc3)/sizeof(*hc3); i++) {
        for (j = 0; j < 3; j++)
            args[j] = getarg();

        printf("hc3: %i: %x %x %x\n", i, args[0], args[1], args[2]);

        hc3[i](args[0], args[1], args[2]);
    }
}


/*
 * Hypercalls with 4 arguments
 */
hc4_t hc4[] = {
    (hc4_t) HYPERVISOR_mmu_update,
    (hc4_t) HYPERVISOR_mmuext_op,
    //(hc4_t) HYPERVISOR_set_callbacks,
    //(hc4_t) HYPERVISOR_update_descriptor,
    //(hc4_t) HYPERVISOR_update_va_mapping,
};

void hc4_fuzzer(void) {
    int i, j;
    uint32_t args[4];

    for (i = 0; i < sizeof(hc4)/sizeof(*hc4); i++) {
        for (j = 0; j < 4; j++)
            args[j] = getarg();

        printf("hc4: %i: %x %x %x %x\n", i, args[0], args[1], args[2],
               args[3]);

        hc4[i](args[0], args[1], args[2], args[3]);
    }
}


/*
 * Hypercalls with 5 arguments
 */
hc5_t hc5[] = {
    (hc5_t) HYPERVISOR_update_va_mapping_otherdomain,
};

void hc5_fuzzer(void) {
    int i, j;
    uint32_t args[5];

    for (i = 0; i < sizeof(hc5)/sizeof(*hc5); i++) {
        for (j = 0; j < 5; j++)
            args[j] = getarg();

        printf("hc5: %i: %x %x %x %x %x\n", i, args[0], args[1], args[2],
               args[3], args[4]);

        hc5[i](args[0], args[1], args[2], args[3], args[4]);
    }
}


void (*fuzzer[])(void) = {
    hc1_fuzzer,
    hc2_fuzzer,
    hc3_fuzzer,
    hc4_fuzzer,
    hc5_fuzzer,
};

char buf[65535];

char *evil_buf(char *buf, size_t size) {
    int i, r;

    for (i = 0; i < size; i++) {
        r = rand();
        buf[i] = r;
    }

    return buf;
}

#define _4GB_MEM 4294967295UL
#define _3GB_MEM 3221225471UL
#define _1GB_MEM 1073741823UL
#define _64MB_MEM 67108863UL

uint32_t getarg(void) {
    switch (rand() % 10) {
     case 0:
         return INT_MIN;
     case 1:
         return INT_MAX;
     case 2:
         return UINT_MAX;
     case 3:
         return (uint32_t) NULL;
     case 4:
         return (uint32_t) evil_buf(buf, sizeof(buf));
     case 5:
         /* Xen Hypervisor Memory, top 64MB */
         return (_4GB_MEM - _64MB_MEM) + (rand() % _64MB_MEM);
     case 6:
         /* Kernel Memory, 3GB to 4GB - 64MB*/
         return _3GB_MEM + (rand() % (_1GB_MEM - _64MB_MEM));
     case 7:
         /* User Memory, first 3GB */
         return rand() % _3GB_MEM;
     default:
         return rand();
    }
}

int main(int argc, char **argv) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    srand(tv.tv_usec);

    printf("start fuzzing with seed %x...\n", tv.tv_usec);

    while (1)
        fuzzer[rand() % (sizeof(fuzzer)/sizeof(*fuzzer))]();
}
