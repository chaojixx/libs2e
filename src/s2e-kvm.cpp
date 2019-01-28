///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///


#include "s2e-kvm.h"

namespace s2e {
namespace kvm {

// clang-format off
static uint32_t s_msr_list [] = {
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,
    MSR_IA32_APICBASE,
    MSR_EFER,
    MSR_STAR,
    MSR_PAT,
    MSR_VM_HSAVE_PA,
    #ifdef TARGET_X86_64
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_FMASK,
    MSR_FSBASE,
    MSR_GSBASE,
    MSR_KERNELGSBASE,
    #endif
    MSR_MTRRphysBase(0),
    MSR_MTRRphysBase(1),
    MSR_MTRRphysBase(2),
    MSR_MTRRphysBase(3),
    MSR_MTRRphysBase(4),
    MSR_MTRRphysBase(5),
    MSR_MTRRphysBase(6),
    MSR_MTRRphysBase(7),
    MSR_MTRRphysMask(0),
    MSR_MTRRphysMask(1),
    MSR_MTRRphysMask(2),
    MSR_MTRRphysMask(3),
    MSR_MTRRphysMask(4),
    MSR_MTRRphysMask(5),
    MSR_MTRRphysMask(6),
    MSR_MTRRphysMask(7),
    MSR_MTRRfix64K_00000,
    MSR_MTRRfix16K_80000,
    MSR_MTRRfix16K_A0000,
    MSR_MTRRfix4K_C0000,
    MSR_MTRRfix4K_C8000,
    MSR_MTRRfix4K_D0000,
    MSR_MTRRfix4K_D8000,
    MSR_MTRRfix4K_E0000,
    MSR_MTRRfix4K_E8000,
    MSR_MTRRfix4K_F0000,
    MSR_MTRRfix4K_F8000,
    MSR_MTRRdefType,
    MSR_MCG_STATUS,
    MSR_MCG_CTL,
    MSR_TSC_AUX,
    MSR_IA32_MISC_ENABLE,
    MSR_MC0_CTL,
    MSR_MC0_STATUS,
    MSR_MC0_ADDR,
    MSR_MC0_MISC
};

/* Array of valid (function, index) entries */
static uint32_t s_cpuid_entries[][2] = {
    {0, (uint32_t) -1},
    {1, (uint32_t) -1},
    {2, (uint32_t) -1},
    {4, 0},
    {4, 1},
    {4, 2},
    {4, 3},
    {5, (uint32_t) -1},
    {6, (uint32_t) -1},
    {7, (uint32_t) -1},
    {9, (uint32_t) -1},
    {0xa, (uint32_t) -1},
    {0xd, (uint32_t) -1},
    {0x80000000, (uint32_t) -1},
    {0x80000001, (uint32_t) -1},
    {0x80000002, (uint32_t) -1},
    {0x80000003, (uint32_t) -1},
    {0x80000004, (uint32_t) -1},
    {0x80000005, (uint32_t) -1},
    {0x80000006, (uint32_t) -1},
    {0x80000008, (uint32_t) -1},
    {0x8000000a, (uint32_t) -1},
    {0xc0000000, (uint32_t) -1},
    {0xc0000001, (uint32_t) -1},
    {0xc0000002, (uint32_t) -1},
    {0xc0000003, (uint32_t) -1},
    {0xc0000004, (uint32_t) -1}
};
// clang-format on


int S2EKVM::GetApiVersion(void)
{
    return KVM_API_VERSION;
}

int S2EKVM::CheckExtension(int capability)
{
    switch (capability) {
        case KVM_CAP_NR_MEMSLOTS: {
            return MAX_MEMORY_SLOTS;
        } break;

        case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
        case KVM_CAP_MP_STATE:
        case KVM_CAP_EXT_CPUID:
        case KVM_CAP_SET_TSS_ADDR:
        case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
        case KVM_CAP_USER_MEMORY:
        case KVM_CAP_NR_VCPUS:
        case KVM_CAP_MAX_VCPUS:

        // We don't really need to support this call, just pretend that we do.
        // The real exit will be done through our custom KVM_CAP_FORCE_EXIT.
        case KVM_CAP_IMMEDIATE_EXIT:

        /* libs2e-specific calls */
        case KVM_CAP_DBT:
        case KVM_CAP_MEM_RW:
        case KVM_CAP_FORCE_EXIT:
            return 1;

#ifdef CONFIG_SYMBEX
        case KVM_CAP_MEM_FIXED_REGION:
        case KVM_CAP_DISK_RW:
        case KVM_CAP_CPU_CLOCK_SCALE:
            return 1;
#endif

// Per-path disk state support is only available with symbex builds.
// Can't write snapshot files there.
#ifdef CONFIG_SYMBEX_MP
        case KVM_CAP_DEV_SNAPSHOT:
            return 1;
#endif

        default:
#ifdef SE_KVM_DEBUG_INTERFACE
            printf("Unsupported cap %x\n", capability);
#endif
            return -1;
    }
}

int S2EKVM::CreateVM()
{
    /* Reserve a dummy file descriptor */
    int fd = open("/dev/null", O_RDWR | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        goto err1;
    }

#ifdef CONFIG_SYMBEX
    init_s2e_libcpu_interface(&g_sqi);
#endif

    cpu_register_io(&g_io);
    tcg_exec_init(0);
    s2e_kvm_init_log_level();

    x86_cpudef_setup();

/* We want the default libcpu CPU, not the KVM one. */
#if defined(TARGET_X86_64)
    g_cpu_env = env = cpu_x86_init("qemu64-s2e");
#elif defined(TARGET_I386)
    g_cpu_env = env = cpu_x86_init("qemu32-s2e");
#else
#error unknown architecture
#endif
    if (!env) {
        printf("Could not create cpu\n");
        goto err2;
    }

    g_cpu_env->v_apic_base = 0xfee00000;
    g_cpu_env->size = sizeof(*g_cpu_env);

    if (s2e_kvm_init_cpu_lock() < 0) {
        exit(-1);
    }

    init_clocks();

    if (s2e_kvm_init_timer_thread() < 0) {
        exit(-1);
    }

    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = s2e_kvm_cpu_exit_signal;

    if (sigaction(CPU_EXIT_SIGNAL, &act, NULL) < 0) {
        perror("Could not initialize cpu exit signal");
        exit(-1);
    }

#ifdef CONFIG_SYMBEX
    g_s2e_shared_dir = getenv("S2E_SHARED_DIR");
    if (!g_s2e_shared_dir) {
        fprintf(stderr, "Warning: S2E_SHARED_DIR environment variable was not specified, "
                        "using %s\n",
                CONFIG_LIBCPU_DATADIR);
        g_s2e_shared_dir = CONFIG_LIBCPU_DATADIR;
    }

    s2e_init();

    // Call it twice, because event pointers are only known
    // after s2e is inited.
    init_s2e_libcpu_interface(&g_sqi);

    s2e_register_cpu(env);

    s2e_init_device_state();
    s2e_init_timers();

    s2e_initialize_execution(g_execute_always_klee);
    s2e_register_dirty_mask((uint64_t) get_ram_list_phys_dirty(), get_ram_list_phys_dirty_size() >> TARGET_PAGE_BITS);
    s2e_on_initialization_complete();
#endif

    do_cpu_init(env);

    return fd;

err2:
    close(fd);
err1:
    return fd;
}

int S2EKVM::GetVCPUMemoryMapSize(void)
{
    return 0x10000; /* Some magic value */
}

int S2EKVM::GetMSRIndexList(struct kvm_msr_list *list)
{
    if (list->nmsrs == 0) {
        list->nmsrs = sizeof(s_msr_list) / sizeof(s_msr_list[0]);
    } else {
        for (int i = 0; i < list->nmsrs; ++i) {
            list->indices[i] = s_msr_list[i];
        }
    }

    return 0;
}

int S2EKVM::GetSupportedCPUID(struct kvm_cpuid2 *cpuid)
{
#ifdef SE_KVM_DEBUG_CPUID
    printf("%s\n", __FUNCTION__);
#endif

    unsigned int nentries = sizeof(s_cpuid_entries) / sizeof(s_cpuid_entries[0]);
    if (cpuid->nent < nentries) {
        errno = E2BIG;
        return -1;
    } else if (cpuid->nent >= nentries) {
        cpuid->nent = nentries;
        // errno = ENOMEM;
        // return -1;
    }

    for (unsigned i = 0; i < nentries; ++i) {
        struct kvm_cpuid_entry2 *e = &cpuid->entries[i];
        cpu_x86_cpuid(env, s_cpuid_entries[i][0], s_cpuid_entries[i][1], &e->eax, &e->ebx, &e->ecx, &e->edx);

        e->flags = 0;
        e->index = 0;
        if (s_cpuid_entries[i][1] != -1) {
            e->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
            e->index = s_cpuid_entries[i][1];
        }
        e->function = s_cpuid_entries[i][0];

#ifdef SE_KVM_DEBUG_CPUID
        print_cpuid2(e);
#endif
    }

    return 0;
}

static void *S2EKVM::TimerCb(void *param) {
    while (!s_s2e_exiting) {
        usleep(100 * 1000);

        // Required for shutdown, otherwise kvm clients may get stuck
        // Also required to give a chance timers to run
        s2e_kvm_send_cpu_exit_signal();
    }

    s_timer_exited = true;
    return NULL;
}

int S2EKVM::InitTimerThread(void)
{
    int ret;
    pthread_attr_t attr;

    ret = pthread_attr_init(&attr);
    if (ret < 0) {
        fprintf(stderr, "Could not init thread attributes\n");
        goto err1;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret < 0) {
        fprintf(stderr, "Could not set detached state for thread\n");
        goto err1;
    }

    ret = pthread_create(&s_timer_thread, &attr, TimerCb, NULL);
    if (ret < 0) {
        fprintf(stderr, "could not create timer thread\n");
        goto err1;
    }

    pthread_attr_destroy(&attr);

err1:
    return ret;
}

int S2EKVM::ioctl(int fd, int request, uint64_t arg1)
{
    int ret = -1;

    switch ((uint32_t) request) {
        case KVM_GET_API_VERSION:
            return GetApiVersion();

        case KVM_CHECK_EXTENSION:
            ret = CheckExtension(arg1);
            if (ret < 0) {
                errno = 1;
            }
            break;

        case KVM_CREATE_VM: {
            int tmpfd = CreateVM();
            if (tmpfd < 0) {
                printf("Could not create vm fd (errno=%d %s)\n", errno, strerror(errno));
                exit(-1);
            }
            g_kvm_vm_fd = tmpfd;
            ret = tmpfd;
        } break;

        case KVM_GET_VCPU_MMAP_SIZE: {
            ret = GetVCPUMemoryMapSize();
        } break;

        case KVM_GET_MSR_INDEX_LIST: {
            ret = GetMSRIndexList((kvm_msr_list *) arg1);
        } break;

        case KVM_GET_SUPPORTED_CPUID: {
            ret = GetSupportedCPUID((kvm_cpuid2 *) arg1);
        } break;

        default: {
            fprintf(stderr, "libs2e: unknown KVM IOCTL %x\n", request);
            exit(-1);
        }
    }

    return ret;
}

}
}
