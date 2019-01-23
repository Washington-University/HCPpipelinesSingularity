/*******************************************************************************
    Copyright (c) 2015 NVIDIA Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

#include "uvm8_api.h"
#include "uvm8_global.h"
#include "uvm8_gpu_replayable_faults.h"
#include "uvm8_mem.h"
#include "uvm8_perf_events.h"
#include "uvm8_procfs.h"
#include "uvm8_thread_context.h"
#include "uvm8_va_range.h"
#include "uvm8_kvmalloc.h"
#include "uvm8_mmu.h"
#include "uvm8_perf_heuristics.h"
#include "uvm8_pmm_sysmem.h"
#include "uvm8_ats_ibm.h"
#include "uvm8_migrate.h"
#include "nv_uvm_interface.h"

static int uvm8_ats_mode = -1;
module_param(uvm8_ats_mode, int, S_IRUGO);
MODULE_PARM_DESC(uvm8_ats_mode, "Override the default ATS (Address Translation Services) "
                                "UVM mode by disabling (0) or enabling (1)");

uvm_global_t g_uvm_global;
static struct UvmOpsUvmEvents g_exported_uvm8_ops;
static bool g_ops_registered = false;

static NV_STATUS uvm8_register_callbacks(void)
{
    NV_STATUS status = NV_OK;

    g_exported_uvm8_ops.startDevice = NULL;
    g_exported_uvm8_ops.stopDevice  = NULL;
    g_exported_uvm8_ops.isrTopHalf  = uvm8_isr_top_half;

    // Register the UVM callbacks with the main GPU driver:
    status = uvm_rm_locked_call(nvUvmInterfaceRegisterUvmCallbacks(&g_exported_uvm8_ops));
    if (status != NV_OK)
        return status;

    g_ops_registered = true;
    return NV_OK;
}

// Calling this function more than once is harmless:
static void uvm8_unregister_callbacks(void)
{
    if (g_ops_registered) {
        uvm_rm_locked_call_void(nvUvmInterfaceDeRegisterUvmOps());
        g_ops_registered = false;
    }
}

static void ats_init(const UvmPlatformInfo *platform_info)
{
    g_uvm_global.ats.supported = platform_info->atsSupported;

    switch (uvm8_ats_mode) {
        case 0:
            // Always allow override to disable
            g_uvm_global.ats.enabled = false;
            break;

        case 1:
            g_uvm_global.ats.enabled = platform_info->atsSupported;
            if (!g_uvm_global.ats.enabled) {
                pr_info("This platform does not support ATS. Ignoring uvm8_ats_mode.\n");
            }
            else if (!UVM_KERNEL_SUPPORTS_IBM_ATS()) {
                // TODO: Bug 2103667: After ATS development stabilizes and
                //       systems have been upgraded, disallow this case.
                pr_info("WARNING: This kernel has incomplete ATS support and you may experience system instability or "
                        "crashes. This option will be removed in the future.\n");
            }

            break;

        default:
            // Pick the default
            g_uvm_global.ats.enabled = platform_info->atsSupported && UVM_KERNEL_SUPPORTS_IBM_ATS();
            break;
    }
}

NV_STATUS uvm_global_init(void)
{
    NV_STATUS status;
    UvmPlatformInfo platform_info;

    status = uvm_thread_context_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_thread_context_init() failed: %s\n", nvstatusToString(status));

        // We enforce thread contexts to be initialized before any locking API
        // is used. If thread contexts cannot be initialized properly it is not
        // safe to jump into the teardown path as it involves using locking
        // mechanisms.
        return status;
    }

    uvm_mutex_init(&g_uvm_global.global_lock, UVM_LOCK_ORDER_GLOBAL);
    uvm_spin_lock_irqsave_init(&g_uvm_global.gpu_table_lock, UVM_LOCK_ORDER_LEAF);
    uvm_mutex_init(&g_uvm_global.va_spaces.lock, UVM_LOCK_ORDER_VA_SPACES_LIST);
    INIT_LIST_HEAD(&g_uvm_global.va_spaces.list);

    status = uvm_kvmalloc_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_kvmalloc_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = errno_to_nv_status(nv_kthread_q_init(&g_uvm_global.global_q, "UVM global queue"));
    if (status  != NV_OK) {
        UVM_DBG_PRINT("nv_kthread_q_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_procfs_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_procfs_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_rm_locked_call(nvUvmInterfaceSessionCreate(&g_uvm_global.rm_session_handle, &platform_info));
    if (status != NV_OK) {
        UVM_ERR_PRINT("nvUvmInterfaceSessionCreate() failed: %s\n", nvstatusToString(status));
        return status;
    }

    ats_init(&platform_info);
    g_uvm_global.num_simulated_devices = 0;

    status = uvm_gpu_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_gpu_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_pmm_sysmem_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_pmm_sysmem_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_mmu_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_mmu_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_mem_global_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_mem_gloal_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_va_range_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_va_range_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_range_group_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_range_group_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_migrate_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_migrate_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_perf_events_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_perf_events_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    status = uvm_perf_heuristics_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_perf_heuristics_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }

    uvm_ats_ibm_init();

    // This sets up the ISR (interrupt service routine), by hooking into RM's top-half ISR callback. As soon as this
    // call completes, GPU interrupts will start arriving, so it's important to be prepared to receive interrupts before
    // this point:
    status = uvm8_register_callbacks();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm8_register_callbacks failed: %s\n", nvstatusToString(status));
        goto error;
    }

    return status;

error:
    uvm_global_exit();
    return status;
}

void uvm_global_exit(void)
{
    uvm_assert_mutex_unlocked(&g_uvm_global.global_lock);

    uvm8_unregister_callbacks();
    uvm_ats_ibm_exit();
    uvm_perf_heuristics_exit();
    uvm_perf_events_exit();
    uvm_migrate_exit();
    uvm_range_group_exit();
    uvm_va_range_exit();
    uvm_mem_global_exit();
    uvm_pmm_sysmem_exit();
    uvm_gpu_exit();

    if (g_uvm_global.rm_session_handle != 0)
        uvm_rm_locked_call_void(nvUvmInterfaceSessionDestroy(g_uvm_global.rm_session_handle));

    uvm_procfs_exit();

    nv_kthread_q_stop(&g_uvm_global.global_q);

    uvm_assert_mutex_unlocked(&g_uvm_global.va_spaces.lock);
    UVM_ASSERT(list_empty(&g_uvm_global.va_spaces.list));

    uvm_thread_context_exit();
    uvm_kvmalloc_exit();
}

void uvm_global_set_fatal_error_impl(NV_STATUS error)
{
    NV_STATUS previous_error;

    UVM_ASSERT(error != NV_OK);

    previous_error = nv_atomic_cmpxchg(&g_uvm_global.fatal_error, NV_OK, error);

    if (previous_error == NV_OK) {
        UVM_ERR_PRINT("Encountered a global fatal error: %s\n", nvstatusToString(error));
    }
    else {
        UVM_ERR_PRINT("Encountered a global fatal error: %s after a global error has been already set: %s\n",
                nvstatusToString(error), nvstatusToString(previous_error));
    }
}

NV_STATUS uvm_global_reset_fatal_error(void)
{
    if (!uvm_enable_builtin_tests) {
        UVM_ASSERT_MSG(0, "Resetting global fatal error without tests being enabled\n");
        return NV_ERR_INVALID_STATE;
    }

    return nv_atomic_xchg(&g_uvm_global.fatal_error, NV_OK);
}

NV_STATUS uvm_api_is_8_supported(UVM_IS_8_SUPPORTED_PARAMS *params, struct file *filp)
{
    params->is8Supported = 1;
    return NV_OK;
}

bool uvm_pageable_mem_access_supported(uvm_va_space_t *va_space)
{
    // We might have systems with both ATS and HMM support. ATS gets priority.
    if (g_uvm_global.ats.supported)
        return g_uvm_global.ats.enabled;

    return uvm_hmm_is_enabled(va_space);
}

NV_STATUS uvm_api_pageable_mem_access(UVM_PAGEABLE_MEM_ACCESS_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    params->pageableMemAccess = uvm_pageable_mem_access_supported(va_space) ? NV_TRUE : NV_FALSE;
    return NV_OK;
}
