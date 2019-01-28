///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <cpu/kvm.h>

#include <cpu/cpus.h>
#include <cpu/exec.h>
#include <cpu/memory.h>
#include <libcpu-log.h>
#include <timer.h>

#include "coroutine.h"

#ifdef CONFIG_SYMBEX
#include <s2e/monitor.h>
#include <s2e/s2e_block.h>
#include <s2e/s2e_libcpu.h>
#endif

#include <cpu/cpu-common.h>
#include <cpu/i386/cpu.h>
#include <cpu/ioport.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

// #define SE_KVM_DEBUG_IRQ
// #define SE_KVM_DEBUG_DEV_STATE

#include "s2e-kvm-interface.h"

// We may need a very large stack in case of deep expressions.
// Default stack is a few megabytes, it's not enough.
static const uint64_t S2E_STACK_SIZE = 1024 * 1024 * 1024;

// XXX: make this clean
int s2e_dev_save(const void *buffer, size_t size);
int s2e_dev_restore(void *buffer, int pos, size_t size);

extern CPUX86State *env;
extern void *g_s2e;

// Convenience variable to help debugging in gdb.
// env is present in both inside qemu and libs2e, which
// causes confusion.
CPUX86State *g_cpu_env;

#define false 0

int g_signal_pending = 0;

struct stats_t g_stats;

static const int MAX_MEMORY_SLOTS = 32;

// Indicates that the cpu loop returned with a coroutine switch.
// This happens when an instruction had to suspend its execution
// to let the kvm client handle the operation (e.g., mmio, snapshot, etc.).
int g_handling_kvm_cb;

// Indicates that the cpu loop is handling a device state snaphsot load/save.
// This implies that g_handling_kvm_cb is 1.
int g_handling_dev_state;

int g_cpu_state_is_precise = 1;

static const int CPU_EXIT_SIGNAL = SIGUSR2;
bool g_cpu_thread_id_inited = false;
pthread_t g_cpu_thread_id;

static volatile bool s_in_kvm_run = false;
static volatile bool s_s2e_exiting = false;
static volatile bool s_timer_exited = false;


static pthread_t s_timer_thread;

extern struct cpu_io_funcs_t g_io;

static void s2e_kvm_cpu_exit_signal(int signum) {
    env->kvm_request_interrupt_window = 1;
    cpu_exit(env);
}

///
/// \brief s2e_kvm_send_cpu_exit_signal sends a signal
/// to the cpu loop thread in order to exit the cpu loop.
///
/// It is important to use a signal that executes on the
/// same thread as the cpu loop in order to avoid race conditions
/// and complex locking.
///
static void s2e_kvm_send_cpu_exit_signal(void) {
    if (!g_cpu_thread_id_inited) {
        return;
    }

    if (pthread_kill(g_cpu_thread_id, CPU_EXIT_SIGNAL) < 0) {
        abort();
    }
}



#ifdef CONFIG_SYMBEX
#include <s2e/s2e_config.h>
#include <tcg/tcg-llvm.h>

const char *g_s2e_config_file = NULL;
const char *g_s2e_output_dir;
const char *g_s2e_shared_dir = NULL;
int g_execute_always_klee = 0;
int g_s2e_verbose = 0;
int g_s2e_max_processes = 1;

static void s2e_terminate_timer_thread() {
    s_s2e_exiting = true;
    while (!s_timer_exited)
        ;
}

static void s2e_cleanup(void) {
    s2e_terminate_timer_thread();

    if (g_s2e) {
        monitor_close();
        s2e_close();
        g_s2e = NULL;
    }
}

static void s2e_init(void) {
    tcg_llvm_ctx = tcg_llvm_initialize();

    g_s2e_config_file = getenv("S2E_CONFIG");

    if (!g_s2e_config_file) {
        fprintf(stderr, "Warning: S2E_CONFIG environment variable was not specified, "
                        "using the default (empty) config file\n");
    }

    g_s2e_output_dir = getenv("S2E_OUTPUT_DIR");

    int argc = 0;
    char **argv = {NULL};

    if (monitor_init() < 0) {
        exit(-1);
    }

    int unbuffered_stream = 0;
    const char *us = getenv("S2E_UNBUFFERED_STREAM");
    if (us && us[0] == '1') {
        unbuffered_stream = 1;
    }

    const char *max_processes = getenv("S2E_MAX_PROCESSES");
    if (max_processes) {
        g_s2e_max_processes = strtol(max_processes, NULL, 0);
    }

    s2e_initialize(argc, argv, tcg_llvm_ctx, g_s2e_config_file, g_s2e_output_dir, unbuffered_stream, g_s2e_verbose,
                   g_s2e_max_processes);

    s2e_create_initial_state();

    atexit(s2e_cleanup);
}

#endif

/**** /dev/kvm ioctl handlers *******/


///
/// \brief s2e_kvm_init_log_level initializes the libcpu log level.
///
/// This is the same as the -d switch from vanilla QEMU.
///
static void s2e_kvm_init_log_level() {
    loglevel = 0;
    const char *libcpu_log_level = getenv("LIBCPU_LOG_LEVEL");
    if (libcpu_log_level) {
        loglevel = cpu_str_to_log_mask(libcpu_log_level);
    }

    const char *libcpu_log_file = getenv("LIBCPU_LOG_FILE");
    if (libcpu_log_file) {
        logfile = fopen(libcpu_log_file, "w");
        if (!logfile) {
            printf("Could not open log file %s\n", libcpu_log_file);
            exit(-1);
        }
    } else {
        logfile = stdout;
    }
}




/**** vm ioctl handlers *******/





/**** vcpu ioctl handlers *******/


void s2e_kvm_flush_disk(void) {
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_FLUSH_DISK;
    g_handling_dev_state = 1;
    coroutine_yield();
}

void s2e_kvm_save_device_state(void) {
#ifdef SE_KVM_DEBUG_DEV_STATE
    libcpu_log("Saving device state\n");
    log_cpu_state(g_cpu_env, 0);
#endif
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_SAVE_DEV_STATE;
    g_handling_dev_state = 1;
    coroutine_yield();
}

void s2e_kvm_restore_device_state(void) {
#ifdef SE_KVM_DEBUG_DEV_STATE
    libcpu_log("Restoring device state\n");
    log_cpu_state(g_cpu_env, 0);
#endif
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_RESTORE_DEV_STATE;
    g_handling_dev_state = 1;
    coroutine_yield();
}

void s2e_kvm_clone_process(void) {
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_CLONE_PROCESS;

    coroutine_yield();

    g_cpu_thread_id = pthread_self();

    if (s2e_kvm_init_timer_thread() < 0) {
        exit(-1);
    }
}




///
/// \brief s2e_kvm_request_exit triggers an exit from the cpu loop
///
/// In vanilla KVM, the CPU stops executing guest code when there is
/// an external event pending. Execution can stop at any instruction.
///
/// In our emulated KVM, stopping at any instruction is not possible
/// because of TB chaining, threading, etc.
///
/// This may cause missed interrupts. The KVM client is ready to inject an interrupt,
/// but cannot do so because kvm_run has not exited yet. While it is running,
/// several interrupts of different priorities may be queued up. When kvm_run
/// eventually returns, the highest priority interrupt is injected first.
/// Because DBT is much slower than native execution, it often happens
/// that lower priority don't get to run at all, and higher
/// priority ones are missed.
///
/// Since we can't easily replicate KVM's behavior, we resort to doing
/// what vanilla QEMU in DBT mode would do: interrupt the CPU loop when an interrupt
/// is raised so that the interrupt is scheduled asap.
///
/// This requires adding an extra API to KVM. Things that have been tried
/// to avoid adding the extra API, but did not work properly:
/// - Intercept pthread_kill. KVM client may kick the CPU when an interrupt is ready.
/// This is still too slow.
/// - Intercept eventfd. KVM clients call poll eventfds instead of using signals.
/// Polling for them from a separate thread didn't work either.
///
void s2e_kvm_request_exit(void) {
    if (!env) {
        return;
    }

#ifdef SE_KVM_DEBUG_RUN
    printf("s2e_kvm_request_exit\n");
#endif

    s2e_kvm_send_cpu_exit_signal();
}

///
/// \brief s2e_kvm_request_process_exit cleanly exits
/// the process by sending it SIGTERM
///
/// It is not possible to call exit() directly, as this will
/// abort the process in an unclean manner, possibly causing
/// crashes in other threads.
///
/// Instead, we intercept the exit() call from the S2E plugin
/// and transform it into a signal that the process will use
/// to exit cleanly.
///
/// WARNING: this call aborts the cpu loop without cleaning the
/// stack. Any allocated objects there will leak.
///
/// \param original_exit the original exit() syscall function
/// \param code the exit code
///
void s2e_kvm_request_process_exit(exit_t original_exit, int code) {
    s_s2e_exiting = true;

    if (!s_kvm_cpu_coroutine) {
        original_exit(code);
    }

    coroutine_yield();
    abort();
}
