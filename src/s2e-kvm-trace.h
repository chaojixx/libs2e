///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_KVM_TRACE_H

#define S2E_KVM_TRACE_H

#include <inttypes.h>
#include <cpu/kvm.h>

#include "FDManager.h"
#include "s2e-kvm-interface.h"

namespace s2e {
namespace kvm {

class KVMTrace: public IFile {
private:
    ioctl_t m_ioctl;

    KVMTrace() {}

public:
    static IFilePtr Create();

    virtual int ioctl(int fd, int request, uint64_t arg1);
};

class KVMTraceVM: public IFile {
private:
    ioctl_t m_ioctl;

    KVMTraceVM() {}

public:

    virtual int ioctl(int fd, int request, uint64_t arg1);
};


class KVMTraceVCPU: public IFile {
private:
    ioctl_t m_ioctl;

    KVMTraceVCPU() {}

public:

    virtual int ioctl(int fd, int request, uint64_t arg1);
};


}
}

#endif
