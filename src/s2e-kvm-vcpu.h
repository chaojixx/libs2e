///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_KVM_VCPU_H

#define S2E_KVM_VCPU_H

#include <inttypes.h>
#include <cpu/kvm.h>

#include <cpu/i386/cpu.h>
#include <coroutine.h>

#include "FDManager.h"

namespace s2e {
namespace kvm {

class VCPU: public IFile {
private:
    int m_fd;

    CPUX86State *m_env;

    unsigned m_sigmask_size;

    union {
        sigset_t sigset;
        uint8_t bytes[32];
    } m_sigmask;

    pthread_mutex_t m_cpuLock;

    kvm_run *m_cpuBuffer;
    Coroutine *m_coroutine;

    void BlockSignals();
    void UnblockSignals();

    static void SetCpuSegment(SegmentCache *libcpu_seg, const kvm_segment *kvm_seg);
    static void GetCpuSegment(kvm_segment *kvm_seg, const SegmentCache *libcpu_seg);
    static void Get8086Segment(kvm_segment *kvm_seg, const SegmentCache *libcpu_seg);
    static void CoroutineFcn(void *opaque);

    int InitCpuLock(void);

public:
    int GetClock(kvm_clock_data *clock);
    int SetCPUID2(kvm_cpuid2 *cpuid);

    // Defines which signals are blocked during execution of kvm.
    int SetSignalMask(kvm_signal_mask *mask);

    ///
    /// \brief s2e_kvm_vcpu_set_regs set the general purpose registers of the CPU
    ///
    /// libcpu does not track register the program counter and eflags state precisely,
    /// in order to speed up execution. More precisely, it will not update these registers
    /// after each instruction is executed. This has important implications for KVM clients.
    /// When guest code executes an instruction that causes a VM exit (e.g., memory access
    /// to a device), the following happens:
    ///
    /// 1. libcpu suspends the current translation block and calls the I/O handler in libs2e
    /// 2. Functions in s2e-kvm-io.c trigger a coroutine switch to s2e_kvm_vcpu_run,
    ///    which returns to the KVM client
    /// 3. The KVM client handles the I/O emulation
    /// 4. The KVM client re-enters s2e_kvm_vcpu_run, which switches back to the coroutine
    ///    interrupted in step 2.
    /// 5. Execution of the translation block resumes
    ///
    /// During step 3, I/O emulation may want to access the guest cpu register state using
    /// the corresponding KVM APIs. In vanilla KVM, these APIs expect the CPU state to be
    /// fully consistent. However, this consistency is broken in libs2e because of how CPU
    /// emulation works (see explanation above). Luckily, this situation does not usually
    /// happen in practice, as the KVM client reads the CPU state when it is in sync.
    /// This function nevertheless checks for this and prints a warning.
    ///
    /// Same remarks apply for register setters, which may corrupt CPU state if called
    /// at a time where the CPU state is not properly committed.
    ///
    /// In principle, fixing this issue would require calling cpu_restore_state at every
    /// exit point.
    ///
    int SetRegisters(kvm_regs *regs);

    int SetFPU(kvm_fpu *fpu);
    int SetSystemRegisters(kvm_sregs *sregs);
    int SetMSRs(kvm_msrs *msrs);
    int SetMPState(kvm_mp_state *mp);

    int GetRegisters(kvm_regs *regs);
    int GetFPU(kvm_fpu *fpu);
    int GetSystemRegisters(kvm_sregs *sregs);
    int GetMSRs(kvm_msrs *msrs);
    int GetMPState(kvm_mp_state *mp);

    int Run(int vcpu_fd);
    int Interrupt(kvm_interrupt *interrupt);
    int NMI();

    virtual int ioctl(int fd, int request, uint64_t arg1);
    virtual void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
};

}
}

#endif
