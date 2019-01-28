///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_KVM_H

#define S2E_KVM_H

#include <inttypes.h>
#include <cpu/kvm.h>

#include "FDManager.h"

namespace s2e {
namespace kvm {

class S2EKVM: public IFile {
private:
    static void *TimerCb(void *param);
    int InitTimerThread(void);

    S2EKVM() {}

public:
    static IFilePtr Create();

    int GetApiVersion(void);
    int CheckExtension(int capability);
    int CreateVM();
    static int GetVCPUMemoryMapSize(void);
    int GetMSRIndexList(kvm_msr_list *list);
    int GetSupportedCPUID(kvm_cpuid2 *cpuid);

    virtual int ioctl(int fd, int request, uint64_t arg1);
};

}
}

#endif
