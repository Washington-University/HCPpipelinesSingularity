/*******************************************************************************
    Copyright (c) 2018 NVIDIA Corporation

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

#ifndef __UVM8_ATS_IBM_H__
#define __UVM8_ATS_IBM_H__

#include "uvm_linux.h"
#include "uvm8_forward_decl.h"
#include "uvm8_hal_types.h"

// The powerpc kernel APIs to enable ATS were present prior to this callback
// change, but they were still in development. Various bug fixes were needed in
// the kernel and they all went in before this callback change. We can use the
// callback signature as a flag to indicate whether the kernel can support ATS
// in production.
#if defined(NV_PNV_NPU2_INIT_CONTEXT_CALLBACK_RETURNS_VOID)
    #define UVM_KERNEL_SUPPORTS_IBM_ATS() 1
#else
    #define UVM_KERNEL_SUPPORTS_IBM_ATS() 0
#endif

// TODO: Bug 2103667: NV_PNV_NPU2_INIT_CONTEXT_PRESENT is used here instead of
//       UVM_KERNEL_SUPPORTS_IBM_ATS() during the transition from ATS
//       development to ATS production, since development can still enable ATS
//       without the final kernel patches in place. After ATS development
//       stabilizes and systems have been upgraded, this should switch to
//       UVM_KERNEL_SUPPORTS_IBM_ATS().
#if defined(NV_PNV_NPU2_INIT_CONTEXT_PRESENT)
    void uvm_ats_ibm_init(void);
    void uvm_ats_ibm_exit(void);

    // Creates or retains a uvm_ats_ibm_mm_t for current->mm. This prevents the
    // uvm_ats_ibm_mm_t from being freed, but it does not prevent the mm from
    // being freed. The caller is expected to call
    // uvm_ats_ibm_register_gpu_va_space to retain the mm.
    NV_STATUS uvm_ats_ibm_mm_retain(uvm_ats_ibm_mm_t **out_ats_mm);

    // Like uvm_ats_ibm_mm_retain but assumes the caller already has a known-
    // valid ats_mm. This is useful when current->mm might not be ats_mm->mm.
    void uvm_ats_ibm_mm_retain_existing(uvm_ats_ibm_mm_t *ats_mm);

    // Counterpart to uvm_ats_ibm_mm_retain. Releases count references on the
    // ats_mm. The ats_mm may have been freed once this call returns.
    void uvm_ats_ibm_mm_release_count(uvm_ats_ibm_mm_t *ats_mm, NvU64 count);

    void uvm_ats_ibm_mm_lock(uvm_ats_ibm_mm_t *ats_mm);
    void uvm_ats_ibm_mm_unlock(uvm_ats_ibm_mm_t *ats_mm);

    // Lock which must be held over uvm_ats_ibm_register_gpu_va_space. This
    // cannot be taken internally to that function because this lock must be
    // taken before mmap_sem and the VA space lock, so the caller must do it.
    void uvm_ats_ibm_register_lock(uvm_va_space_t *va_space);
    void uvm_ats_ibm_register_unlock(uvm_va_space_t *va_space);

    // Enables ATS access for the gpu_va_space on current->mm.
    // gpu_va_space->ats.ats_mm must have been retained.
    //
    // This function also associates the VA space with the ats_mm, or increments
    // the ref count of that association if already present. If another VA space
    // has already been associated with current->mm, NV_ERR_NOT_SUPPORTED is
    // returned. The association will remain until the final
    // uvm_ats_ibm_unregister_gpu_va_space call in the VA space is made.
    //
    // LOCKING: The ats_ibm_mm lock, uvm_ats_ibm_register_lock, mmap_sem, and
    //          the VA space lock must all be held in exclusive mode.
    NV_STATUS uvm_ats_ibm_register_gpu_va_space(uvm_gpu_va_space_t *gpu_va_space);

    // Disables ATS access for the gpu_va_space. Prior to calling this function,
    // the caller must guarantee that the GPU will no longer make any ATS
    // accesses in this GPU VA space, and that no ATS fault handling will be
    // attempted.
    //
    // LOCKING: The ats_ibm_mm lock must be held. This function may take
    //          the uvm_ats_ibm_register_lock, mmap_sem, and the VA space lock.
    void uvm_ats_ibm_unregister_gpu_va_space(uvm_gpu_va_space_t *gpu_va_space);

    // Request the kernel to handle a fault.
    //
    // LOCKING: mmap_sem must be held.
    NV_STATUS uvm_ats_ibm_service_fault(uvm_gpu_va_space_t *gpu_va_space,
                                        NvU64 fault_addr,
                                        uvm_fault_access_type_t access_type);

#else
    static void uvm_ats_ibm_init(void)
    {

    }

    static void uvm_ats_ibm_exit(void)
    {

    }

    static NV_STATUS uvm_ats_ibm_mm_retain(uvm_ats_ibm_mm_t **out_ats_mm)
    {
        *out_ats_mm = NULL;
        return NV_OK;
    }

    static void uvm_ats_ibm_mm_retain_existing(uvm_ats_ibm_mm_t *ats_mm)
    {

    }

    static void uvm_ats_ibm_mm_release_count(uvm_ats_ibm_mm_t *ats_mm, NvU64 count)
    {

    }

    static void uvm_ats_ibm_mm_lock(uvm_ats_ibm_mm_t *ats_mm)
    {

    }

    static void uvm_ats_ibm_mm_unlock(uvm_ats_ibm_mm_t *ats_mm)
    {

    }

    static void uvm_ats_ibm_register_lock(uvm_va_space_t *va_space)
    {

    }

    static void uvm_ats_ibm_register_unlock(uvm_va_space_t *va_space)
    {

    }

    static NV_STATUS uvm_ats_ibm_register_gpu_va_space(uvm_gpu_va_space_t *gpu_va_space)
    {
        return NV_OK;
    }

    static void uvm_ats_ibm_unregister_gpu_va_space(uvm_gpu_va_space_t *gpu_va_space)
    {

    }

    static NV_STATUS uvm_ats_ibm_service_fault(uvm_gpu_va_space_t *gpu_va_space,
                                               NvU64 fault_addr,
                                               uvm_fault_access_type_t access_type)
    {
        return NV_ERR_NOT_SUPPORTED;
    }
#endif // NV_PNV_NPU2_INIT_CONTEXT_PRESENT

static void uvm_ats_ibm_mm_release(uvm_ats_ibm_mm_t *ats_mm)
{
    uvm_ats_ibm_mm_release_count(ats_mm, 1);
}

#endif // __UVM8_ATS_IBM_H__
