///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <inttypes.h>

#include "s2e-kvm-vcpu.h"

#define BIT(n) (1 << (n))

namespace s2e {
namespace kvm {

int VCPU::InitCpuLock(void) {
    int ret = pthread_mutex_init(&m_cpuLock, nullptr);
    if (ret < 0) {
        fprintf(stderr, "Could not init cpu lock\n");
    }

    return ret;
}


#ifdef SE_KVM_DEBUG_CPUID
static void print_cpuid2(struct kvm_cpuid_entry2 *e) {
    printf("cpuid function=%#010" PRIx32 " index=%#010" PRIx32 " flags=%#010" PRIx32 " eax=%#010" PRIx32
           " ebx=%#010" PRIx32 " ecx=%#010" PRIx32 " edx=%#010" PRIx32 "\n",
           e->function, e->index, e->flags, e->eax, e->ebx, e->ecx, e->edx);
}
#endif


int VCPU::GetClock(kvm_clock_data *clock)
{
    assert(false && "Not implemented");
}

int VCPU::SetCPUID2(kvm_cpuid2 *cpuid)
{
    /**
     * QEMU insists on using host cpuid flags when running in KVM mode.
     * We want to use those set in DBT mode instead.
     * TODO: for now, we have no way to configure custom flags.
     * Snapshots will not work if using anything other that defaults.
     */

    /// This check ensures that users don't mistakenly use the wrong build of libs2e.
    #if defined(TARGET_X86_64)
        if (cpuid->nent == 15) {
            fprintf(stderr, "libs2e for 64-bit guests is used but the KVM client requested 32-bit features\n");
            exit(1);
        }
    #elif defined(TARGET_I386)
        if (cpuid->nent == 21) {
            fprintf(stderr, "libs2e for 32-bit guests is used but the KVM client requested 64-bit features\n");
            exit(1);
        }
    #else
    #error unknown architecture
    #endif

    return 0;
}

void VCPU::BlockSignals(void) {
    sigdelset(&m_sigmask.sigset, CPU_EXIT_SIGNAL);
    if (pthread_sigmask(SIG_BLOCK, &m_sigmask.sigset, NULL) < 0) {
        abort();
    }
}

void VCPU::UnblockSignals(void) {
    sigaddset(&m_sigmask.sigset, CPU_EXIT_SIGNAL);
    if (pthread_sigmask(SIG_UNBLOCK, &m_sigmask.sigset, NULL) < 0) {
        abort();
    }
}

int VCPU::SetSignalMask(kvm_signal_mask *mask)
{
    // XXX: doesn't seem to matter for typical kvm clients,
    // not sure what the implications of spurious signals are.
    m_sigmask_size = mask->len;
    for (unsigned i = 0; i < mask->len; ++i) {
#ifdef SE_KVM_DEBUG_INTERFACE
        printf("  signals %#04x\n", mask->sigset[i]);
#endif
        m_sigmask.bytes[i] = mask->sigset[i];
    }
    return 0;
}

void VCPU::CoroutineFcn(void *opaque)
{
    VCPU *vcpu = reinterpret_cast<VCPU*>(opaque);
    CPUX86State *env = vcpu->m_env;

#ifdef SE_KVM_DEBUG_IRQ
    static uint64_t prev_mflags = 0;
#endif

    while (1) {
        libcpu_run_all_timers();

        assert(env->current_tb == NULL);

        // XXX: need to save irq state on state switches
        if (env->kvm_irq != -1) {
            if (env->interrupt_request == 0) {
                printf("Forcing IRQ\n");
            }
            env->interrupt_request |= CPU_INTERRUPT_HARD;
        }

#ifdef SE_KVM_DEBUG_IRQ
        if (env->interrupt_request & CPU_INTERRUPT_HARD) {
            printf("Handling IRQ %d req=%#x hflags=%x hflags2=%#x mflags=%#lx tpr=%#x esp=%#lx signal=%d\n",
                   env->kvm_irq, env->interrupt_request, env->hflags, env->hflags2, (uint64_t) env->mflags, env->v_tpr,
                   (uint64_t) env->regs[R_ESP], g_signal_pending);
        }
#endif

        env->kvm_request_interrupt_window |= g_kvm_vcpu_buffer->request_interrupt_window;

#ifdef SE_KVM_DEBUG_IRQ
        prev_mflags = env->mflags;
        uint64_t prev_eip = env->eip;
#endif

        g_cpu_state_is_precise = 0;
        env->exit_request = 0;
        cpu_x86_exec(env);
        g_cpu_state_is_precise = 1;
// printf("cpu_exec return %#x\n", ret);

#ifdef SE_KVM_DEBUG_IRQ
        bool mflags_changed = (prev_mflags != env->mflags);
        if (mflags_changed) {
            printf("mflags changed: %lx old=%lx new=%lx reqwnd=%d peip=%lx, eip=%lx\n", (uint64_t) mflags_changed,
                   (uint64_t) prev_mflags, (uint64_t) env->mflags, g_kvm_vcpu_buffer->request_interrupt_window,
                   (uint64_t) prev_eip, (uint64_t) env->eip);
        }
        prev_mflags = env->mflags;
#endif

        assert(env->current_tb == NULL);

        env->exception_index = 0;
        coroutine_yield();
    }
}

int VCPU::Run(int vcpu_fd)
{
    int ret = 0;

    ++g_stats.kvm_runs;

    if (!s_kvm_cpu_coroutine) {
        s_kvm_cpu_coroutine = coroutine_create(s2e_kvm_cpu_coroutine, S2E_STACK_SIZE);
        if (!s_kvm_cpu_coroutine) {
            fprintf(stderr, "Could not create cpu coroutine\n");
            exit(-1);
        }
    }

    if (!g_cpu_thread_id_inited) {
        g_cpu_thread_id = pthread_self();
        g_cpu_thread_id_inited = true;
    }

    if (s_s2e_exiting) {
        g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_INTR;
        kill(getpid(), SIGTERM);
        errno = EINTR;
        return -1;
    }

    /* Return asap if interrupts can be injected */
    g_kvm_vcpu_buffer->if_flag = (env->mflags & IF_MASK) != 0;
    g_kvm_vcpu_buffer->apic_base = env->v_apic_base;
    g_kvm_vcpu_buffer->cr8 = env->v_tpr;

    g_kvm_vcpu_buffer->ready_for_interrupt_injection = !g_handling_kvm_cb &&
                                                       g_kvm_vcpu_buffer->request_interrupt_window &&
                                                       g_kvm_vcpu_buffer->if_flag && (env->kvm_irq == -1);

    if (g_kvm_vcpu_buffer->ready_for_interrupt_injection) {
#ifdef SE_KVM_DEBUG_IRQ
        printf("%s early ret for ints\n", __FUNCTION__);
#endif
        g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
        return 0;
    }

    block_signals();
    pthread_mutex_lock(&s_cpu_lock);

    s_in_kvm_run = true;

#ifdef SE_KVM_DEBUG_RUN
    if (!g_handling_kvm_cb) {
        printf("%s riw=%d cr8=%#x\n", __FUNCTION__, g_kvm_vcpu_buffer->request_interrupt_window,
               (unsigned) g_kvm_vcpu_buffer->cr8);
    }
#endif

    g_kvm_vcpu_buffer->exit_reason = -1;

    /**
     * Some KVM clients do not set this when calling kvm_run, although the KVM
     * spec says they should. For now, we patch the clients to pass the right value.
     * Eventually, we'll need to figure out how KVM handles it.
     * Having an incorrect (null) APIC base will cause the APIC to get stuck.
     */
    env->v_apic_base = g_kvm_vcpu_buffer->apic_base;
    env->v_tpr = g_kvm_vcpu_buffer->cr8;

    g_handling_kvm_cb = 0;
    g_handling_dev_state = 0;

    coroutine_enter(s_kvm_cpu_coroutine, NULL);

    if (s_s2e_exiting) {
        pthread_mutex_unlock(&s_cpu_lock);
        g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_INTR;
        kill(getpid(), SIGTERM);
        errno = EINTR;
        return -1;
    }

    g_handling_kvm_cb = g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_IO ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_MMIO ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_FLUSH_DISK ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_SAVE_DEV_STATE ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_RESTORE_DEV_STATE ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_CLONE_PROCESS;

    // Might not be NULL if resuming from an interrupted I/O
    // assert(env->current_tb == NULL);

    g_kvm_vcpu_buffer->if_flag = (env->mflags & IF_MASK) != 0;
    g_kvm_vcpu_buffer->apic_base = env->v_apic_base;
    g_kvm_vcpu_buffer->cr8 = env->v_tpr;

    // KVM specs says that we should also check for request for interrupt window,
    // but that causes missed interrupts.
    g_kvm_vcpu_buffer->ready_for_interrupt_injection = !g_handling_kvm_cb &&
                                                       g_kvm_vcpu_buffer->request_interrupt_window &&
                                                       g_kvm_vcpu_buffer->if_flag && (env->kvm_irq == -1);

    if (g_kvm_vcpu_buffer->exit_reason == -1) {
        if (env->halted) {
            g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_HLT;
        } else if (g_kvm_vcpu_buffer->ready_for_interrupt_injection) {
            g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
        } else {
            g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_INTR;
            g_signal_pending = 0;
        }
    }

#if defined(SE_KVM_DEBUG_HLT)
    if (g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_HLT) {
        trace_s2e_kvm_run(g_kvm_vcpu_buffer, ret);
    }
#endif

    assert(g_kvm_vcpu_buffer->exit_reason != 1);

#ifdef SE_KVM_DEBUG_RUN
    if (!g_handling_kvm_cb) {
        printf("%s riw=%d rii=%d er=%#x cr8=%#x\n", __FUNCTION__, g_kvm_vcpu_buffer->request_interrupt_window,
               g_kvm_vcpu_buffer->ready_for_interrupt_injection, g_kvm_vcpu_buffer->exit_reason,
               (unsigned) g_kvm_vcpu_buffer->cr8);
    }
#endif

    if (g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_INTR) {
        // This must be set at the very end, because syscalls might
        // overwrite errno.
        errno = EINTR;
        ret = -1;
    }

    assert(ret >= 0 || errno == EINTR);
    assert(g_kvm_vcpu_buffer->exit_reason != -1);

    s_in_kvm_run = false;

    pthread_mutex_unlock(&s_cpu_lock);
    unblock_signals();

    return ret;
}

int VCPU::Interrupt(kvm_interrupt *interrupt)
{
#ifdef SE_KVM_DEBUG_IRQ
    printf("IRQ %d env->mflags=%lx hflags=%x hflags2=%x ptr=%#x\n", interrupt->irq, (uint64_t) env->mflags, env->hflags,
           env->hflags2, env->v_tpr);
    fflush(stdout);
#endif

    if (m_env->cr[0] & CR0_PE_MASK) {
        assert(interrupt->irq > (m_env->v_tpr << 4));
    }
    assert(!g_handling_kvm_cb);
    assert(!s_in_kvm_run);
    assert(m_env->mflags & IF_MASK);
    assert(!(m_env->interrupt_request & CPU_INTERRUPT_HARD));
    m_env->interrupt_request |= CPU_INTERRUPT_HARD;
    m_env->kvm_irq = interrupt->irq;

    return 0;
}

int VCPU::NMI()
{
    m_env->interrupt_request |= CPU_INTERRUPT_NMI;
    return 0;
}

int VCPU::ioctl(int fd, int request, uint64_t arg1)
{
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_GET_CLOCK: {
            ret = GetClock((kvm_clock_data *) arg1);
        } break;

        case KVM_SET_CPUID2: {
            ret = SetCPUID2((kvm_cpuid2 *) arg1);
        } break;

        case KVM_SET_SIGNAL_MASK: {
            ret = SetSignalMask((kvm_signal_mask *) arg1);
        } break;

        /***********************************************/
        // When the symbolic execution engine needs to take a system snapshot,
        // it must rely on the KVM client to save the device state. That client
        // will typically also save/restore the CPU state. We don't want the client
        // to do that, so in order to not modify the client too much, we ignore
        // the calls to register setters when they are done in the context of
        // device state snapshotting.
        case KVM_SET_REGS: {
            if (g_handling_dev_state) {
                ret = 0;
            } else {
                ret = SetRegisters((kvm_regs *) arg1);
            }
        } break;

        case KVM_SET_FPU: {
            if (g_handling_dev_state) {
                ret = 0;
            } else {
                ret = SetFPU((kvm_fpu *) arg1);
            }
        } break;

        case KVM_SET_SREGS: {
            if (g_handling_dev_state) {
                ret = 0;
            } else {
                ret = SetSystemRegisters((kvm_sregs *) arg1);
            }
        } break;

        case KVM_SET_MSRS: {
            if (g_handling_dev_state) {
                ret = ((kvm_msrs *) arg1)->nmsrs;
            } else {
                ret = SetMSRs((kvm_msrs *) arg1);
            }
        } break;

        case KVM_SET_MP_STATE: {
            if (g_handling_dev_state) {
                ret = 0;
            } else {
                ret = SetMPState((kvm_mp_state *) arg1);
            }
        } break;
        /***********************************************/
        case KVM_GET_REGS: {
            if (g_handling_dev_state) {
                // Poison the returned registers to make sure we don't use
                // it again by accident. We can't just fail the call because
                // the client needs it to save the cpu state (that we ignore).
                memset((void *) arg1, 0xff, sizeof(kvm_regs));
                ret = 0;
            } else {
                ret = GetRegisters((kvm_regs *) arg1);
            }
        } break;

        case KVM_GET_FPU: {
            ret = GetFPU((kvm_fpu *) arg1);
        } break;

        case KVM_GET_SREGS: {
            ret = GetSystemRegisters((kvm_sregs *) arg1);
        } break;

        case KVM_GET_MSRS: {
            ret = GetMSRs((kvm_msrs *) arg1);
        } break;

        case KVM_GET_MP_STATE: {
            ret = GetMPState((kvm_mp_state *) arg1);
        } break;

        /***********************************************/
        case KVM_RUN: {
            return Run(fd);
        } break;

        case KVM_INTERRUPT: {
            ret = Interrupt((kvm_interrupt *) arg1);
        } break;

        case KVM_NMI: {
            ret = NMI();
        } break;

        default: {
            fprintf(stderr, "libs2e: unknown KVM VCPU IOCTL vcpu %d request=%#x arg=%#" PRIx64 " ret=%#x\n", fd,
                    request, arg1, ret);
            exit(-1);
        }
    }

    return ret;
}

void *VCPU::mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    int real_size = KVM::GetVCPUMemoryMapSize();
    assert(real_size == len);
    assert(m_cpuBuffer);

    return m_cpuBuffer;
}

}
}
