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

#include "uvm_common.h"
#include "uvm_linux.h"
#include "uvm_linux_ioctl.h"
#include "uvm8_init.h"
#include "uvm8_lock.h"
#include "uvm8_api.h"
#include "uvm8_va_range.h"
#include "uvm8_va_space.h"
#include "uvm8_populate_pageable.h"

// Populate the pages of the given vma that overlap with the [start:end) range.
//
// Locking: mmap_sem must be held in read or write mode
static NV_STATUS populate_pageable_vma(unsigned long start,
                                       unsigned long end,
                                       struct vm_area_struct *vma,
                                       int min_prot)
{
    unsigned long vma_size;
    unsigned long vma_num_pages;
    const bool is_writable = (vma->vm_flags) & VM_WRITE;
    const bool min_prot_ok = (vma->vm_flags & min_prot) == min_prot;
    bool uvm_managed_vma;
    long ret;

    UVM_ASSERT(PAGE_ALIGNED(start));
    UVM_ASSERT(PAGE_ALIGNED(end));
    UVM_ASSERT(vma->vm_end > start);
    UVM_ASSERT(vma->vm_start < end);
    uvm_assert_mmap_sem_locked(&current->mm->mmap_sem);

    if (!min_prot_ok)
        return NV_ERR_INVALID_ADDRESS;

    // Adjust to input range boundaries
    start = max(start, vma->vm_start);
    end = min(end, vma->vm_end);

    vma_size = end - start;
    vma_num_pages = vma_size / PAGE_SIZE;

    // If the input vma is managed by UVM, temporarily remove the record
    // associated with the locking of mmap_sem, in order to avoid a "locked 
    // twice" validation error triggered when also acquiring mmap_sem in the 
    // page fault handler. The page fault is caused by get_user_pages.
    uvm_managed_vma = uvm_file_is_nvidia_uvm(vma->vm_file);
    if (uvm_managed_vma)
        uvm_record_unlock_mmap_sem_read(&current->mm->mmap_sem);

    ret = NV_GET_USER_PAGES(start, vma_num_pages, is_writable, 0, NULL, NULL);

    if (uvm_managed_vma)
        uvm_record_lock_mmap_sem_read(&current->mm->mmap_sem);

    if (ret < 0)
        return errno_to_nv_status(ret);

    // We couldn't populate all pages, return error
    if (ret < vma_num_pages)
        return NV_ERR_NO_MEMORY;

    return NV_OK;
}

// Populate all the pages in the given range by calling get_user_pages. If any
// of the pages was not populated, we return NV_ERR_NO_MEMORY.
//
// Locking: mmap_sem must be held in read or write mode
NV_STATUS uvm_populate_pageable(const unsigned long start, const unsigned long length, int min_prot)
{
    struct vm_area_struct *vma;
    const unsigned long end = start + length;
    unsigned long prev_end = end;

    UVM_ASSERT(PAGE_ALIGNED(start));
    UVM_ASSERT(PAGE_ALIGNED(length));
    uvm_assert_mmap_sem_locked(&current->mm->mmap_sem);

    vma = find_vma_intersection(current->mm, start, end);

    // VMAs are validated and populated one at a time, since they may have
    // different protection flags
    // Validation of VM_SPECIAL flags is delegated to get_user_pages
    for (; vma && (vma->vm_start <= prev_end); vma = vma->vm_next) {
        NV_STATUS status = populate_pageable_vma(start, end, vma, min_prot);

        if (status != NV_OK)
            return status;

        if (vma->vm_end >= end)
            return NV_OK;

        prev_end = vma->vm_end;
    }

    // Input range not fully covered by VMAs.
    return NV_ERR_INVALID_ADDRESS;
}

NV_STATUS uvm_api_populate_pageable(const UVM_POPULATE_PAGEABLE_PARAMS *params, struct file *filp)
{
    NV_STATUS status;
    bool allow_managed;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);

    if (params->flags && (params->flags != UVM_POPULATE_PAGEABLE_FLAG_ALLOW_MANAGED))
        return NV_ERR_INVALID_ARGUMENT;

    // Population of managed ranges is only allowed for test purposes. The goal
    // is to validate that it is possible to populate pageable ranges backed by
    // VMAs with the VM_MIXEDMAP or VM_DONTEXPAND special flags set. But since
    // there is no portable way to force allocation of such memory from user
    // space, and it is not safe to change the flags of an already created
    // VMA from kernel space, we take advantage of the fact that managed ranges
    // have both special flags set at creation time (see uvm_mmap)
    allow_managed = params->flags & UVM_POPULATE_PAGEABLE_FLAG_ALLOW_MANAGED;
    if (allow_managed && !uvm_enable_builtin_tests) {
        UVM_INFO_PRINT("Test flag set for UVM_POPULATE_PAGEABLE. Did you mean to insmod with uvm_enable_builtin_tests=1?\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Check size, alignment and overflow. VMA validations are performed by
    // populate_pageable
    if (uvm_api_range_invalid(params->base, params->length))
        return NV_ERR_INVALID_ADDRESS;

    // mmap_sem is needed to traverse the vmas in the input range and call into
    // get_user_pages
    uvm_down_read_mmap_sem(&current->mm->mmap_sem);

    if (allow_managed || uvm_va_space_range_empty(va_space, params->base, params->base + params->length - 1))
        status = uvm_populate_pageable(params->base, params->length, VM_READ | VM_WRITE);
    else
        status = NV_ERR_INVALID_ADDRESS;

    uvm_up_read_mmap_sem(&current->mm->mmap_sem);

    return status;
}
