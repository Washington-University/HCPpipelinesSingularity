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

#include "uvm8_lock.h"
#include "uvm8_kvmalloc.h"
#include "uvm8_va_space.h"
#include "uvm8_va_space_mm.h"
#include "uvm8_ats_ibm.h"
#include "uvm_common.h"

// TODO: Bug 2103667: Switch to UVM_KERNEL_SUPPORTS_IBM_ATS(). See the similar
//       comment in uvm8_ats_ibm.h.
#if defined(NV_PNV_NPU2_INIT_CONTEXT_PRESENT)

// ================================= Overview ==================================
// This block comment describes temporary issues with the npu API, and the UVM
// workarounds required until those issues are resolved upstream.
//
// The basic problem is a mismatch between the UVM APIs and the original
// expectations of the npu APIs. The npu APIs in question are:
//
// - pnv_npu2_init_context      Sets up an {mm, GPU} pair for ATS access
// - pnv_npu2_destroy_context   Tears down ATS access from an {mm, GPU} pair and
//                              provides a callback when the mm is torn down.
//
// These two APIs were written with the following expectations:
//
// 1) They would be called at most once per mm, per GPU
//
// 2) All npu_inits in an mm were called before all npu_destroys in that mm
//
// 3) The caller passed the same callback function and arg parameters to all
//    npu_inits for a given mm.
//
// If these expectations are violated various types of badness can happen,
// ranging from GPU ATS accesses not working to kernel crashes.
//
// npu_init corresponds to GPU VA space register, and npu_destroy corresponds to
// GPU VA space unregister. Since GPU VA spaces can come and go arbitrarily in
// a UVM VA space, expectations #1 and #2 are violated.
//
// Expectation #3 can also be violated but the scenario is a little more
// complicated. The callback args are unique to the UVM VA space, i.e. the UVM
// file. But a process can create multiple UVM files and register a GPU VA space
// in each under the same mm, which would cause the previous callback args to be
// overwritten since the npu layer only stores one set of callbacks per mm.
//
// =============================== Requirements ================================
//
// Requirement #1: Serialize all calls to pnv_npu2_init_context and
//                 pnv_npu2_destroy_context under the same mm.
//
//     This is required because these functions have no thread safety. A race
//     could cause npu_destroy to free the npu_context while npu_init is still
//     using it.
//
//     Note that this requirement includes serializing all combinations of
//     npu_init/npu_init, npu_init/npu_destroy, and npu_destroy/npu_destroy.
//     npu_init/npu_init will already be serialized by mmap_sem.
//
//     The VA space lock is not sufficient for this, because
//     A) It does not serialize different VA spaces in the same mm
//     B) It cannot be held across npu_destroy, since npu_destroy may depend on
//        the VA space lock.
//
//     mmap_sem is not sufficient for this either, because
//     A) Like the VA space lock, mmap_sem cannot be held across npu_destroy
//        since npu_destroy may depend on mmap_sem.
//     B) npu_destroy might perform the last mmdrop and free the mm.
//
// Requirement #2: Disallow more than one pnv_npu2_init_context on the same
//                 {mm, GPU} without an intervening pnv_npu2_destroy_context on
//                 that {mm, GPU}.
//
//     We must avoid this sequence:
//     Thread 0             Thread 1
//     ----------------     ----------------
//     npu_init(devA)
//                          npu_init(devA)
//     npu_destroy(devA)
//                          npu_destroy(devA)
//
//     Some of the npu state is refcounted, but some isn't. Each npu_destroy
//     will remove the TCE ID for that {mm, GPU} regardless of how many prior
//     npu_inits there were, yet each npu_init bumps the refcount of the
//     npu_context itself.
//
//     Note that this requirement is already met if both threads are operating
//     in the same UVM VA space, since the normal VA space checks prevent double
//     GPU VA space register on the same GPU. This is a problem for separate UVM
//     VA spaces in the same mm, however.
//
// Requirement #3: If pnv_npu2_init_context has been called on {mm,
//                 UVM VA space A} for at least one GPU, disallow all calls to
//                 pnv_npu2_init_context on {mm, UVM VA space B} until
//                 pnv_npu2_destroy_context has been called on all GPUs in {mm,
//                 UVM VA space A}.
//
//     npu_init(va_space_0, devA)
//     npu_init(va_space_1, devB)   // Not ok
//     npu_destroy(va_space0, devA)
//     npu_init(va_space_1, devB)   // Ok
//
//     Our callback args are unique to the UVM VA space. The npu layer only
//     stores one set of args per mm, so an npu_init in UVM va_space_1 under the
//     same mm will clobber UVM va_space_0's args.
//
// ================================= Approach ==================================
//
// The first time a GPU VA space is registered within an mm, we add an entry
// to a global table which ties that mm to that UVM VA space. This is safe
// because the mm object is valid until we make the final npu_destroy call.
// Subsequent GPU VA space registrations verify that the {mm, va_space} pair
// matches. If not, an error is returned. This meets requirement #2 and #3. The
// functions implementing this are:
//  uvm_ats_ibm_mm_retain / uvm_ats_ibm_mm_release
//  uvm_ats_ibm_register_gpu_va_space / uvm_ats_ibm_unregister_gpu_va_space
//
// Requirement #1 is solved by putting a per-entry lock in that global table.
// The lock is held across each call to npu_init and npu_destroy. The helpers
// uvm_ats_ibm_mm_lock and uvm_ats_ibm_mm_unlock operate on this lock. Since
// the VA space lock is dropped several times during GPU VA space unregister,
// and since npu_destroy has a dependency on both the VA space lock and
// mmap_sem, this lock must be above both.
//
// TODO: Bug 2062970: All of the handling described above (the uvm_ats_ibm_mm
//       functions) should be removed when the npu code is fixed and all
//       development systems have been upgraded.

static struct
{
    // The active VA spaces are kept in a list rather than some structure
    // which is better at lookups because lists are the simplest option to get
    // right and this code is intended to be temporary. This list is searched
    // relatively infrequently (GPU VA space register/unregister) and generally
    // doesn't have very many elements (number of UVM VA spaces in the system).
    struct list_head list;
    uvm_mutex_t lock;
} g_uvm_ats_ibm_mm_table;

struct uvm_ats_ibm_mm_struct
{
    // This mm is used only as a key in the lookup. It is never dereferenced,
    // because it might not be valid when va_space == NULL.
    struct mm_struct *mm;

    // Protected by g_uvm_ats_ibm_mm_table::lock. Prevents the uvm_ats_ibm_mm_t
    // from removal, but does not prevent the mm from being freed.
    NvU64 refcount;

    // Node storage in g_uvm_ats_ibm_mm_table::list. Protected by
    // g_uvm_ats_ibm_mm_table::lock.
    struct list_head list_node;

    // Lock serializing pnv_npu2_init_context and pnv_npu2_destroy_context with
    // each other and themselves on the same mm.
    uvm_mutex_t reg_unreg_lock;

    // va_space associated with this ats_mm and the number of times that
    // va_space has been registered in this ats_mm. These fields are protected
    // by reg_unreg_lock. The mm is valid until va_space_refcount goes to 0, in
    // which case va_space will be set to NULL.
    uvm_va_space_t *va_space;
    NvU64 va_space_refcount;
};

static bool g_ats_ibm_initialized = false;

void uvm_ats_ibm_init(void)
{
    INIT_LIST_HEAD(&g_uvm_ats_ibm_mm_table.list);
    uvm_mutex_init(&g_uvm_ats_ibm_mm_table.lock, UVM_LOCK_ORDER_LEAF);
    g_ats_ibm_initialized = true;
}

void uvm_ats_ibm_exit(void)
{
    if (!g_ats_ibm_initialized)
        return;

    UVM_ASSERT(list_empty(&g_uvm_ats_ibm_mm_table.list));
    uvm_assert_mutex_unlocked(&g_uvm_ats_ibm_mm_table.lock);
}

static uvm_ats_ibm_mm_t *uvm_ats_ibm_mm_find(struct mm_struct *mm)
{
    uvm_ats_ibm_mm_t *ats_mm = NULL;

    uvm_assert_mutex_locked(&g_uvm_ats_ibm_mm_table.lock);

    list_for_each_entry(ats_mm, &g_uvm_ats_ibm_mm_table.list, list_node) {
        if (ats_mm->mm == mm)
            return ats_mm;
    }

    return NULL;
}

NV_STATUS uvm_ats_ibm_mm_retain(uvm_ats_ibm_mm_t **out_ats_mm)
{
    uvm_ats_ibm_mm_t *ats_mm = NULL;
    NV_STATUS status = NV_OK;

    *out_ats_mm = NULL;

    UVM_ASSERT(g_uvm_global.ats.enabled);

    // TODO: Bug 2062970: If the kernel has all required fixes, skip ats_mm
    //       locking.
    if (UVM_KERNEL_SUPPORTS_IBM_ATS())
        return NV_OK;

    uvm_mutex_lock(&g_uvm_ats_ibm_mm_table.lock);

    ats_mm = uvm_ats_ibm_mm_find(current->mm);
    if (ats_mm) {
        UVM_ASSERT(ats_mm->refcount > 0);
        ++ats_mm->refcount;
    }
    else {
        ats_mm = uvm_kvmalloc_zero(sizeof(*ats_mm));
        if (ats_mm) {
            ats_mm->mm = current->mm;
            ats_mm->refcount = 1;
            uvm_mutex_init(&ats_mm->reg_unreg_lock, UVM_LOCK_ORDER_ATS_IBM_MM);
            list_add_tail(&ats_mm->list_node, &g_uvm_ats_ibm_mm_table.list);
        }
        else {
            status = NV_ERR_NO_MEMORY;
        }
    }

    uvm_mutex_unlock(&g_uvm_ats_ibm_mm_table.lock);

    if (status == NV_OK)
        *out_ats_mm = ats_mm;
    return status;
}

void uvm_ats_ibm_mm_retain_existing(uvm_ats_ibm_mm_t *ats_mm)
{
    if (!ats_mm)
        return;

    UVM_ASSERT(g_uvm_global.ats.enabled);
    UVM_ASSERT(!UVM_KERNEL_SUPPORTS_IBM_ATS());

    uvm_mutex_lock(&g_uvm_ats_ibm_mm_table.lock);

    UVM_ASSERT(uvm_ats_ibm_mm_find(ats_mm->mm) == ats_mm);
    UVM_ASSERT(ats_mm->refcount > 0);
    UVM_ASSERT(ats_mm->va_space);
    ++ats_mm->refcount;

    uvm_mutex_unlock(&g_uvm_ats_ibm_mm_table.lock);
}

void uvm_ats_ibm_mm_release_count(uvm_ats_ibm_mm_t *ats_mm, NvU64 count)
{
    if (!ats_mm)
        return;

    UVM_ASSERT(g_uvm_global.ats.enabled);
    UVM_ASSERT(!UVM_KERNEL_SUPPORTS_IBM_ATS());

    uvm_mutex_lock(&g_uvm_ats_ibm_mm_table.lock);

    UVM_ASSERT(ats_mm->refcount >= count);
    ats_mm->refcount -= count;
    if (ats_mm->refcount == 0) {
        UVM_ASSERT(ats_mm->va_space == NULL);
        UVM_ASSERT(ats_mm->va_space_refcount == 0);
        list_del(&ats_mm->list_node);
        uvm_assert_mutex_unlocked(&ats_mm->reg_unreg_lock);
        uvm_kvfree(ats_mm);
    }

    uvm_mutex_unlock(&g_uvm_ats_ibm_mm_table.lock);
}

void uvm_ats_ibm_mm_lock(uvm_ats_ibm_mm_t *ats_mm)
{
    if (ats_mm) {
        UVM_ASSERT(g_uvm_global.ats.enabled);
        UVM_ASSERT(!UVM_KERNEL_SUPPORTS_IBM_ATS());
        uvm_mutex_lock(&ats_mm->reg_unreg_lock);
    }
}

void uvm_ats_ibm_mm_unlock(uvm_ats_ibm_mm_t *ats_mm)
{
    if (ats_mm) {
        UVM_ASSERT(g_uvm_global.ats.enabled);
        UVM_ASSERT(!UVM_KERNEL_SUPPORTS_IBM_ATS());
        uvm_mutex_unlock(&ats_mm->reg_unreg_lock);
    }
    else {
        uvm_assert_unlocked_order(UVM_LOCK_ORDER_ATS_IBM_MM);
    }
}

void uvm_ats_ibm_register_lock(uvm_va_space_t *va_space)
{
    if (UVM_KERNEL_SUPPORTS_IBM_ATS())
        uvm_mutex_lock(&va_space->mm_state.ats_reg_unreg_lock);
}

void uvm_ats_ibm_register_unlock(uvm_va_space_t *va_space)
{
    if (UVM_KERNEL_SUPPORTS_IBM_ATS())
        uvm_mutex_unlock(&va_space->mm_state.ats_reg_unreg_lock);
}

// This function is called under two circumstances:
// 1) By the kernel when the mm is about to be torn down
// 2) By the last pnv_npu2_destroy_context in a VA space
//
// We are guaranteed that this function is called by at least one of those
// paths. We are not guaranteed to be called by both paths, but it is possible
// that they are called concurrently.
static void npu_release(struct npu_context *npu_context, void *va_mm)
{
    uvm_va_space_mm_t *va_space_mm = (uvm_va_space_mm_t *)va_mm;
    UVM_ASSERT(g_uvm_global.ats.enabled);

    // There are some subtleties identifying whether we're on the mm teardown
    // path or the GPU VA space unregister path. uvm_va_space_mm_shutdown will
    // figure that out.
    //
    // The requirement for this callback are that, once we return:
    // 1) GPUs will not issue any more translated ATS memory accesses under this
    //    mm_struct
    // 2) GPUs will not issue any more ATRs under that mm_struct
    // 3) pnv_npu2_handle_fault will no longer be called on this npu_context
    //
    // uvm_va_space_mm_shutdown provides all of those guarantees.
    uvm_va_space_mm_shutdown(va_space_mm);
}

#ifdef NV_PNV_NPU2_INIT_CONTEXT_CALLBACK_RETURNS_VOID
    static struct npu_context *pnv_npu2_init_context_wrapper(struct pci_dev *gpdev, unsigned long flags, void *priv)
    {
        return pnv_npu2_init_context(gpdev, flags, npu_release, priv);
    }
#else
    static struct npu_context *npu_release_ret(struct npu_context *npu_context, void *va_mm)
    {
        npu_release(npu_context, va_mm);

        // The NPU code doesn't do anything with this returned value
        return NULL;
    }

    static struct npu_context *pnv_npu2_init_context_wrapper(struct pci_dev *gpdev, unsigned long flags, void *priv)
    {
        return pnv_npu2_init_context(gpdev, flags, npu_release_ret, priv);
    }
#endif

NV_STATUS uvm_ats_ibm_register_gpu_va_space(uvm_gpu_va_space_t *gpu_va_space)
{
    uvm_va_space_t *va_space = gpu_va_space->va_space;
    uvm_ats_ibm_mm_t *ats_mm = gpu_va_space->ats.ats_mm;
    struct npu_context *npu_context;
    NV_STATUS status;

    if (!gpu_va_space->ats.enabled)
        return NV_OK;

    UVM_ASSERT(g_uvm_global.ats.enabled);
    UVM_ASSERT(uvm_gpu_va_space_state(gpu_va_space) == UVM_GPU_VA_SPACE_STATE_ACTIVE);
    uvm_assert_mmap_sem_locked_write(&current->mm->mmap_sem);
    uvm_assert_rwsem_locked_write(&va_space->lock);

    if (UVM_KERNEL_SUPPORTS_IBM_ATS()) {
        uvm_assert_mutex_locked(&va_space->mm_state.ats_reg_unreg_lock);
    }
    else {
        UVM_ASSERT(ats_mm);
        uvm_assert_mutex_locked(&ats_mm->reg_unreg_lock);
        UVM_ASSERT(ats_mm->refcount);
        UVM_ASSERT(ats_mm->mm == current->mm);

        if (ats_mm->va_space)
            UVM_ASSERT(ats_mm->va_space_refcount > 0);
        else
            UVM_ASSERT(ats_mm->va_space_refcount == 0);

        // Fulfill requirements #2 and #3 above by latching the va_space to this
        // mm and not allowing others to take it.
        if (ats_mm->va_space && ats_mm->va_space != va_space)
            return NV_ERR_NOT_SUPPORTED;
    }

    // We use the va_space_mm as the callback arg to pnv_npu2_init_context, so
    // we have to register it first to make sure it's created. This thread holds
    // a reference on current->mm, so we're safe to use the mm here even before
    // pnv_npu2_init_context takes its reference.
    status = uvm_va_space_mm_register(va_space);
    if (status != NV_OK)
        return status;

    // We're holding both the VA space lock and mmap_sem on this path so we
    // can't call uvm_va_space_mm_unregister if we hit some error. Tell the
    // caller to do it if that becomes necessary.
    gpu_va_space->did_va_space_mm_register = true;

    // The callback values are shared by all devices under the npu, so we must
    // pass the same values to each one. See requirement #3 above.
    //
    // Note that the callback cannot be invoked until we're done with this
    // ioctl, since the only paths which invoke the callback are GPU VA space
    // unregister and mm teardown. The GPU VA space can't be unregistered while
    // we hold the VA space lock, and the mm can't be torn down while it's
    // active on this thread.
    npu_context = pnv_npu2_init_context_wrapper(gpu_va_space->gpu->pci_dev,
                                                (MSR_DR | MSR_PR | MSR_HV),
                                                gpu_va_space->va_space->mm_state.va_space_mm);
    if (IS_ERR(npu_context)) {
        int err = PTR_ERR(npu_context);

        // We'll get -EINVAL if the callback value (va_space_mm) differs from
        // the one already registered to the npu_context associated with this
        // mm. That can only happen when multiple VA spaces attempt registration
        // within the same process, which is disallowed and should return
        // NV_ERR_NOT_SUPPORTED.
        if (err == -EINVAL)
            return NV_ERR_NOT_SUPPORTED;
        return errno_to_nv_status(err);
    }

    if (!UVM_KERNEL_SUPPORTS_IBM_ATS()) {
        if (!ats_mm->va_space)
            ats_mm->va_space = va_space;
        ++ats_mm->va_space_refcount;
    }

    gpu_va_space->ats.npu_context = npu_context;
    return NV_OK;
}

void uvm_ats_ibm_unregister_gpu_va_space(uvm_gpu_va_space_t *gpu_va_space)
{
    uvm_va_space_t *va_space = gpu_va_space->va_space;
    uvm_va_space_mm_t *va_space_mm;

    if (!gpu_va_space->did_va_space_mm_register) {
        UVM_ASSERT(!gpu_va_space->ats.npu_context);
        return;
    }

    UVM_ASSERT(gpu_va_space->ats.enabled);
    UVM_ASSERT(va_space);

    uvm_ats_ibm_register_lock(va_space);

    // Calling pnv_npu2_destroy_context may invoke uvm_va_space_mm_shutdown,
    // which may operate on this va_space_mm. We have to make sure the
    // va_space_mm remains valid until mm_shutdown is done by calling
    // uvm_va_space_mm_unregister.
    va_space_mm = uvm_va_space_mm_unregister(va_space);

    if (gpu_va_space->ats.npu_context) {
        uvm_ats_ibm_mm_t *ats_mm = gpu_va_space->ats.ats_mm;
        UVM_ASSERT(uvm_gpu_va_space_state(gpu_va_space) == UVM_GPU_VA_SPACE_STATE_DEAD);

        if (!UVM_KERNEL_SUPPORTS_IBM_ATS()) {
            UVM_ASSERT(ats_mm);
            UVM_ASSERT(ats_mm->refcount);
            UVM_ASSERT(ats_mm->va_space_refcount);
            UVM_ASSERT(ats_mm->va_space == va_space);
            uvm_assert_mutex_locked(&ats_mm->reg_unreg_lock);
        }

        // This call may in turn call back into npu_release, which may take
        // mmap_sem and the VA space lock. That sequence is the reason we can't
        // be holding those locks on this path.
        pnv_npu2_destroy_context(gpu_va_space->ats.npu_context, gpu_va_space->gpu->pci_dev);
        gpu_va_space->ats.npu_context = NULL;

        if (!UVM_KERNEL_SUPPORTS_IBM_ATS()) {
            if (--ats_mm->va_space_refcount == 0) {
                // The npu_context had been keeping ats_mm->mm valid, but we
                // just destroyed the last npu_context in this va_space so the
                // mm could now be freed with us having a stale mm pointer in
                // g_uvm_ats_ibm_mm_table. That entry will be removed with the
                // soon to-happen uvm_ats_ibm_mm_release call, but we have a
                // window in which the mm pointer could be freed, reallocated,
                // and associated with a new va_space in an entirely new and
                // unrelated process.
                //
                // That new process will be serialized by the ats_mm lock since
                // it would use the same mm pointer to look up the ats_mm. We
                // clear the ats_mm->va_space here so the register in the new
                // process won't fail.
                ats_mm->va_space = NULL;
            }
        }
    }

    uvm_ats_ibm_register_unlock(va_space);
    uvm_va_space_mm_drop(va_space_mm);
}

NV_STATUS uvm_ats_ibm_service_fault(uvm_gpu_va_space_t *gpu_va_space,
                                    NvU64 fault_addr,
                                    uvm_fault_access_type_t access_type)
{
    unsigned long flags;
    uintptr_t addr;
    unsigned long fault_status = 0;
    int err;

    UVM_ASSERT(g_uvm_global.ats.enabled);
    UVM_ASSERT(gpu_va_space->ats.enabled);

    // TODO: Bug 2103669: Service more than a single fault at a time
    flags = (unsigned long)((access_type >= UVM_FAULT_ACCESS_TYPE_WRITE) ? NPU2_WRITE : 0);
    addr = (uintptr_t)fault_addr;

    err = pnv_npu2_handle_fault(gpu_va_space->ats.npu_context, &addr, &flags, &fault_status, 1);
    if (err == -EFAULT) {
        // pnv_npu2_handle_fault returns -EFAULT when one of the VAs couldn't be
        // serviced. We have to inspect the per-page fault_status field for the
        // specific error.

        // TODO: Bug 2103669: If we service more than a single fault at a
        //       time and there's an error on at least one of the pages,
        //       we'll have to pick which error to use.
        return errno_to_nv_status(fault_status);
    }

    return errno_to_nv_status(err);
}

#endif // NV_PNV_NPU2_INIT_CONTEXT_PRESENT
