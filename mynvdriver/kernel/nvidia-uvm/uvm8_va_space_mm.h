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

#ifndef __UVM8_VA_SPACE_MM_H__
#define __UVM8_VA_SPACE_MM_H__

#include "uvm_linux.h"
#include "uvm8_forward_decl.h"
#include "nv-kref.h"

struct uvm_va_space_mm_struct
{
    uvm_va_space_t *va_space;
    struct mm_struct *mm;

    // Refcount for uvm_va_space_mm_register/uvm_va_space_mm_unregister
    NvU32 registered_count;

    // Refcount for uvm_va_space_mm_retain/uvm_va_space_mm_release
    NvU32 retained_count;

    // Wait queue for threads waiting for retainers to finish (retained_count
    // going to 0).
    wait_queue_head_t wait_queue;

    // Refcount for this memory object
    nv_kref_t kref;

    // Set by uvm_va_space_mm_shutdown when the mm tears down
    bool mm_is_dead;

    // State which is only injected by test ioctls
    struct
    {
        // Whether uvm_va_space_mm_shutdown should do a timed wait for other
        // threads to arrive.
        bool delay_shutdown;

        bool verbose;

        // Number of threads which have called uvm_va_space_mm_shutdown. Only
        // used when delay_shutdown is true.
        atomic_t num_mm_shutdown_threads;
    } test;
};

// Registers current->mm with this va_space. This does not itself take a
// reference on the mm, so the caller is responsible for handling that and for
// calling uvm_va_space_mm_unregister before dropping the mm reference.
//
// Each successful call to uvm_va_space_mm_register is refcounted, so multiple
// calls are allowed as long as the mm matches. If mm A has already been
// registered and mm B is current, NV_ERR_NOT_SUPPORTED will be returned.
//
// The VA space lock must be held for write.
NV_STATUS uvm_va_space_mm_register(uvm_va_space_t *va_space);

// Decrements the register count taken by uvm_va_space_mm_register, potentially
// de-associating the mm from the va_space. If this happens, subsequent calls to
// uvm_va_space_mm_retain will return NULL and this function won't return until
// all in-flight retainers have called uvm_va_space_mm_release.
//
// Since retainer threads may operate on the mm and the VA space, the caller
// must not hold either mmap_sem or the VA space lock.
//
// If this may be the last uvm_va_space_mm_unregister call on this VA space, the
// caller must guarantee prior to calling this function that all GPUs in this VA
// space have stopped making accesses to this mm, and will not be able to make
// accesses until uvm_va_space_mm_register is called again.
//
// This function does *not* drop a reference on the va_space_mm allocation: even
// if the returned va_space_mm was removed from the VA space, the object will
// remain valid in memory until uvm_va_space_mm_drop is called. The caller must
// pair all unregister calls with a uvm_va_space_mm_drop call. This separation
// is necessary for callers which may operate on the va_space_mm (for example
// from a callback thread) during unregister.
//
// Locking: This function may take both mmap_sem and the VA space lock.
uvm_va_space_mm_t *uvm_va_space_mm_unregister(uvm_va_space_t *va_space);

// Releases the allocation refcount on the va_space_mm object, potentially
// freeing it. This call is required iff uvm_va_space_mm_unregister was called.
void uvm_va_space_mm_drop(uvm_va_space_mm_t *va_space_mm);

// Retains the current mm registered with this VA space. If no mm is currently
// registered, NULL is returned. Otherwise, the returned mm will remain valid
// for normal use (locking mmap_sem, find_vma, get_user_pages, etc) until
// uvm_va_space_mm_release is called.
//
// It is NOT necessary to hold the VA space lock when calling this function.
uvm_va_space_mm_t *uvm_va_space_mm_retain(uvm_va_space_t *va_space);

// Counterpart to uvm_va_space_mm_retain. After this call, the mm must not be
// used again without another call to uvm_va_space_mm_retain.
void uvm_va_space_mm_release(uvm_va_space_mm_t *va_space_mm);

// Helper which handles a NULL va_space_mm
static struct mm_struct *uvm_va_space_mm_get_mm(uvm_va_space_mm_t *va_space_mm)
{
    if (va_space_mm)
        return va_space_mm->mm;
    return NULL;
}

// Handles the va_space_mm's mm being torn down while the VA space still exists.
// Subsequent calls to uvm_va_space_mm_retain will return NULL and this function
// won't return until all in-flight retainers have called
// uvm_va_space_mm_release.
//
// uvm_va_space_mm_unregister must still be called. It is safe to call this
// function concurrently with the unregister functions, but the caller must take
// care with dropping the va_space_mm if so.
//
// It is assumed that the caller may not be able to differentiate mm shutdown
// paths vs some other teardown path such as GPU VA space unregister ioctl or VA
// space destroy. This function will figure out whether the mm shutdown really
// needs to happen.
//
// After this call returns on an teardown path, the VA space is essentially
// dead. GPUs cannot make any new memory accesses in registered GPU VA spaces,
// and no more GPU faults which are attributed to this VA space will arrive.
// Additionally, no more registration within the VA space is allowed (GPU, GPU
// VA space, or channel).
//
// Locking: This function may take both mmap_sem and the VA space lock.
void uvm_va_space_mm_shutdown(uvm_va_space_mm_t *va_space_mm);

NV_STATUS uvm8_test_va_space_mm_retain(UVM_TEST_VA_SPACE_MM_RETAIN_PARAMS *params, struct file *filp);
NV_STATUS uvm8_test_va_space_mm_delay_shutdown(UVM_TEST_VA_SPACE_MM_DELAY_SHUTDOWN_PARAMS *params, struct file *filp);

#endif // __UVM8_VA_SPACE_MM_H__
