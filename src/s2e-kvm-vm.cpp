///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "s2e-kvm-vm.h"

uint64_t g_clock_start = 0;
uint64_t g_clock_offset = 0;

namespace s2e {
namespace kvm {

int VM::EnableCapability(kvm_enable_cap *cap)
{
    printf("Enable capability not supported %d\n", cap->cap);
    errno = 1;
    return -1;
}

int VM::CreateVirtualCPU()
{
    // TODO: implement this
    size_t size = s2e_kvm_get_vcpu_mmap_size();
    g_kvm_vcpu_buffer = (kvm_run *) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    // Magic file descriptor
    // We don't need a real one, just something to recognize ioctl calls.
    g_kvm_vcpu_fd = vm_fd + 234234;
    cpu_exec_init_all();
    return g_kvm_vcpu_fd;
}

int VM::SetTSSAddress(uint64_t tss_addr)
{
#ifdef SE_KVM_DEBUG_INTERFACE
    printf("Setting tss addr %#" PRIx64 " not implemented yet\n", tss_addr);
#endif
    return 0;
}

int VM::SetUserMemoryRegion(kvm_userspace_memory_region *region)
{
    // This must never be called while another thread is in the cpu loop
    // because it will cause race conditions with the TLB and the ram structures.
    s2e_kvm_request_exit();
    pthread_mutex_lock(&s_cpu_lock);

    assert(!s_in_kvm_run);
    tlb_flush(env, 1);
    mem_desc_unregister(region->slot);
    mem_desc_register(region);

    pthread_mutex_unlock(&s_cpu_lock);

    return 0;
}

int VM::MemoryReadWrite(kvm_mem_rw *mem)
{
#if !defined(CONFIG_SYMBEX_MP)
    if (!mem->is_write) {
        // Fast path for reads
        // TODO: also do it for writes
        memcpy((void *) mem->dest, (void *) mem->source, mem->length);
        return 0;
    }
#endif

    s2e_kvm_request_exit();
    pthread_mutex_lock(&s_cpu_lock);
    cpu_host_memory_rw(mem->source, mem->dest, mem->length, mem->is_write);
    pthread_mutex_unlock(&s_cpu_lock);
    return 0;
}

int VM::RegisterFixedRegion(kvm_fixed_region *region)
{
#ifdef CONFIG_SYMBEX_MP
    s2e_register_ram2(region->name, region->host_address, region->size, region->flags & KVM_MEM_SHARED_CONCRETE);
#endif
    return 0;
}

int VM::GetDirtyLog(kvm_dirty_log *log)
{
    s2e_kvm_request_exit();

    const MemoryDesc *r = mem_desc_get_slot(log->slot);

    if (s_s2e_exiting) {
        // This may happen if we are called from an exit handler, e.g., if
        // plugin code called exit() from the cpu loop. We don't want
        // to deadlock in this case, so return conservatively all dirty.
        memset(log->dirty_bitmap, 0xff, (r->kvm.memory_size >> TARGET_PAGE_BITS) / 8);
        return 0;
    }

    pthread_mutex_trylock(&s_cpu_lock);

    cpu_physical_memory_get_dirty_bitmap((uint8_t *) log->dirty_bitmap, r->ram_addr, r->kvm.memory_size,
                                         VGA_DIRTY_FLAG);

    cpu_physical_memory_reset_dirty(r->ram_addr, r->ram_addr + r->kvm.memory_size - 1, VGA_DIRTY_FLAG);

    pthread_mutex_unlock(&s_cpu_lock);
    return 0;
}

int VM::SetIdentityMapAddress(uint64_t addr)
{
    assert(false && "Not implemented");
}

int VM::SetClock(kvm_clock_data *clock)
{
    g_clock_start = clock->clock;
    g_clock_offset = cpu_get_real_ticks();
    return 0;
}

int VM::GetClock(kvm_clock_data *clock)
{
    clock->clock = cpu_get_real_ticks() - g_clock_offset + g_clock_start;
    clock->flags = 0;
    return 0;
}

int VM::IOEventFD(kvm_ioeventfd *event)
{
#ifdef SE_KVM_DEBUG_INTERFACE
    printf("kvm_ioeventd datamatch=%#llx addr=%#llx len=%d fd=%d flags=%#" PRIx32 "\n", event->datamatch, event->addr,
           event->len, event->fd, event->flags);
#endif
    return -1;
}

int VM::DiskReadWrite(kvm_disk_rw *d)
{
#ifdef CONFIG_SYMBEX
    if (d->is_write) {
        d->count = s2e_bdrv_write(nullptr, d->sector, (uint8_t *) d->host_address, d->count);
    } else {
        d->count = s2e_bdrv_read(nullptr, d->sector, (uint8_t *) d->host_address, d->count);
    }
    return 0;
#else
    return -1;
#endif
}

int VM::DeviceSnapshot(kvm_dev_snapshot *s)
{
#ifdef CONFIG_SYMBEX_MP
    if (s->is_write) {
        return s2e_dev_save((void *) s->buffer, s->size);
    } else {
        return s2e_dev_restore((void *) s->buffer, s->pos, s->size);
    }
#else
    return -1;
#endif
}

int VM::SetClockScalePointer(unsigned *scale)
{
#ifdef CONFIG_SYMBEX
    if (!scale) {
        return -1;
    }

    g_sqi.exec.clock_scaling_factor = scale;
    return 0;
#else
    return -1;
#endif
}

int VM::ioctl(int fd, int request, uint64_t arg1)
{
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_CHECK_EXTENSION:
            ret = m_kvm->CheckExtension(arg1);
            if (ret < 0) {
                errno = 1;
            }
            break;

        case KVM_SET_TSS_ADDR: {
            ret = SetTSSAddress(arg1);
        } break;

        case KVM_CREATE_VCPU: {
            ret = CreateVirtualCPU();
        } break;

        case KVM_SET_USER_MEMORY_REGION: {
            ret = SetUserMemoryRegion((kvm_userspace_memory_region *) arg1);
        } break;

        case KVM_SET_CLOCK: {
            ret = SetClock((kvm_clock_data *) arg1);
        } break;

        case KVM_GET_CLOCK: {
            ret = GetClock((kvm_clock_data *) arg1);
        } break;

        case KVM_ENABLE_CAP: {
            ret = EnableCapability((kvm_enable_cap *) arg1);
        } break;

        case KVM_IOEVENTFD: {
            ret = IOEventFD((kvm_ioeventfd *) arg1);
        } break;

        case KVM_SET_IDENTITY_MAP_ADDR: {
            ret = SetIdentityMapAddress(arg1);
        } break;

        case KVM_GET_DIRTY_LOG: {
            ret = GetDirtyLog((kvm_dirty_log *) arg1);
        } break;

        case KVM_MEM_RW: {
            ret = MemoryReadWrite((kvm_mem_rw *) arg1);
        } break;

        case KVM_FORCE_EXIT: {
            s2e_kvm_request_exit();
            ret = 0;
        } break;

        case KVM_MEM_REGISTER_FIXED_REGION: {
            ret = RegisterFixedRegion((kvm_fixed_region *) arg1);
        } break;

        case KVM_DISK_RW: {
            ret = DiskReadWrite((kvm_disk_rw *) arg1);
        } break;

        case KVM_DEV_SNAPSHOT: {
            ret = DeviceSnapshot((kvm_dev_snapshot *) arg1);
        } break;

        case KVM_SET_CLOCK_SCALE: {
            ret = SetClockScalePointer((unsigned *) arg1);
        } break;

        default: {
            fprintf(stderr, "libs2e: unknown KVM VM IOCTL %x\n", request);
            exit(-1);
        }
    }

    return ret;
}

}
}
