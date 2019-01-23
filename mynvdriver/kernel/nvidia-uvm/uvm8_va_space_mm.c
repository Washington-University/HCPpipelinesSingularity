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
#include "uvm8_kvmalloc.h"
#include "uvm8_va_space.h"
#include "uvm8_va_space_mm.h"
#include "uvm8_test.h"
#include "uvm8_test_ioctl.h"

//
// This comment block describes some implementation rationale. See the header
// for the API descriptions.
//
// ========================= Pointer vs Embedded State =========================
//
// The uvm_va_space_mm is a pointer in the VA space rather than having its state
// embedded in the VA space. Either approach could work, but using a separate
// allocation per va_space_mm "instance" solves a number of ABA problems.
//
// Consider the following example:
//
// Thread A             Thread B        Thread C
// ----------           ----------      ----------
// Register
//                      Retain
// Unregister
// - Stop new retainers
// - Wait for B
//                                      Register
//
// The second register from thread C would have to wake up thread A and tell it
// to ignore pending retainers. Thread C can't simply allow new retainers
// without waking up thread A, because otherwise A's wait may never end if we
// had a constant stream of new retainers. Thread C also can't wait for B to
// finish, since C holds the VA space lock which may prevent B from completing
// its work.
//
// The difficulty compounds if thread C immediately unregistered and started
// waiting itself. If A took a while to wake back up after being told to abort,
// A would have to handle cleaning things up properly anyway.
//
// A dedicated pointer with its own wait queue and retainer count solves these
// problems if it's removed from the VA space whenever the unregister count goes
// to 0. It adds some new complexity of data management (see
// uvm_va_space_mm_unregister and uvm_va_space_mm_drop), but the tradeoff
// seems preferable.
//
// Note that having a separate pointer means that there could be multiple
// va_space_mm objects alive at a given time pointing to the same VA space. The
// VA space would only track to the most recent of them, however.
//
//
// ============== Using va_space_mm vs current->mm on ioctl paths ==============
//
// The ioctl paths such as UVM_MIGRATE and UVM_SET_ACCESSED_BY have a choice of
// operating on va_space_mm or current->mm, which matters when those paths
// attempt to create CPU mappings. A wrong choice means that ioctl won't be able
// to create CPU mappings.
//
// Generally the paths use current->mm, not va_space_mm. Some reasons for this:
//
// 1) va_space_mm tends to only be valid when pageable memory is supported, so
//    we must be able to handle cases in which the va_space_mm will never be
//    present.
//
// 2) On ATS systems, the va_space_mm only becomes valid on GPU VA space
//    registration, but CPU mappings could be created before that.
//
// 3) It is unlikely in practice for a real application to have a performance
//    case in which the ioctls are invoked from a process other than the one
//    which created the mappings.
//
//
// ============================ Handling mm teardown ===========================
//
// mmu_notifiers call the mm release callback both when the mm is really getting
// shut down, and whenever mmu_notifier_unregister is called. This has several
// consequences, including that these two paths can race. If they do race, they
// wait for each other to finish (real teardown of the mm won't start until the
// mmu_notifier_unregister's callback has returned, and mmu_notifier_unregister
// won't return until the mm release callback has returned).
//
// When the mm is really getting torn down, uvm_va_space_mm_shutdown is expected
// to stop all GPU memory accesses to that mm and stop servicing faults in that
// mm. This essentially shuts down the VA space, though it remains valid until
// the file is closed.
//
// The UVM driver may call the mmu_notifier_unregister equivalent either during
// an ioctl, such as UvmUnregisterGpuVaSpace, or during VA space destroy (file
// close). This means we must be careful not to trigger full VA space mm
// shutdown when we're on an ioctl path, since we want the VA space to still be
// usable if the user just calls UvmUnregisterGpuVaSpace then
// UvmRegisterGpuVaSpace again. However, since calling mmu_notifier_unregister
// on an ioctl path turns off our future mm release callback, we must be careful
// to make the same guarantees on the ioctl path as on the mm release path (GPUs
// can no longer access the mm).
//
// Here is a table of the various teardown scenarios:
//
//                                              Can race                Can shut
//                                              with mm                 down VA
// Scenario                                     teardown   current->mm  space
// -----------------------------------------------------------------------------
// 1) Process exit (mm teardown, file open)        -          NULL        Yes
// 2) ioctl in original mm                         No        orig mm      No
// 3) ioctl in different mm                        Yes       diff mm      No
// 4) Explicit file close in original mm           No        orig mm      Yes
// 5) Explicit file close in different mm          Yes       diff mm      Yes
// 6) Implicit file close (exit) in original mm    No         NULL        Yes
// 7) Implicit file close (exit) in different mm   Yes        NULL        Yes
//
// We don't care about shutting down the VA space on file close, since the VA
// space is getting destroyed anyway. uvm_va_space_mm_shutdown thus uses
// current->mm == NULL as a flag to tell whether it should shut down the VA
// space.
//
// At a high level, the sequence of operations to perform during mm teardown is:
//
// 1) Stop all channels
//      - Prevents new faults and accesses on non-MPS
// 2) Detach all channels
//      - Prevents pending faults from being translated to this VA space
//      - Non-replayable faults will be dropped so no new ones can arrive
//      - Access counter notifications will be prevented from getting new
//        translations to this VA space. Pending entries may attempt to retain
//        the mm, but will drop the notification if they can't be serviced.
// 3) Flush the fault buffer
//      - The only reason to flush the fault buffer is to avoid spurious
//        cancels. If we didn't flush the fault buffer before marking the mm
//        as dead, then remaining faults which require the mm would be
//        cancelled. Since the faults might be stale, we would record cancel
//        events which didn't really happen (the access didn't happen after
//        the mm died). By flushing we clear out all stale faults, and in
//        the case of MPS, cancel real faults after.
// 4) UnsetPageDir
//      - Prevents new accesses on MPS
// 5) Make mm as dead
//      - Prevents new retainers from using the mm. There won't be any more on
//        the fault handling paths, but there could be others in worker threads.
//
// Here are some tables of each step in the sequence, and what operations can
// still be performed after each step. This is all from the perspective of a
// single VA space. "Untranslated" means that the fault entry has not been
// translated to a uvm_va_space yet.
//
// Replayable non-MPS Behavior:
//
//                  Can              Pending         Pending         Can be
//                  access   Can     untranslated    translated      servicing
//                  memory   fault   faults          faults          faults
// -----------------------------------------------------------------------------
// Shutdown start   Yes      Yes     Service         Service         Yes
// Stop channels    No       No      Service [1]     Service [1]     Yes [1]
// Detach channels  No       No      Flush buffer    Service [1]     Yes [1], [2]
// Flush buffer     No       No      None possible   None possible   No
// UnsetPageDir     No       No      None possible   None possible   No
//
//
// Replayable MPS Behavior:
//
//                  Can              Pending         Pending         Can be
//                  access   Can     untranslated    translated      servicing
//                  memory   fault   faults          faults          faults
// -----------------------------------------------------------------------------
// Shutdown start   Yes      Yes     Service         Service         Yes
// Stop channels    Yes      Yes     Service         Service         Yes
// Detach channels  Yes      Yes     Cancel, flush   Service         Yes
// Flush buffer     Yes      Yes     Cancel, flush   None possible   No
// UnsetPageDir     No [3]   Yes     Cancel, flush   None possible   No
//
//
// [1]: All pending faults in this VA space are stale since channel stop
//      preempted the context.
// [2]: Faults in this VA space can't be serviced concurrently with detach since
//      detach holds the VA space lock in write mode. Faults in other VA spaces
//      can be serviced, and stale faults in this VA space can resume service
//      after detach is done.
// [3]: Due to the nature of MPS, remaining work which had started under the VA
//      space could still execute and attempt to make memory accesses. However,
//      since the PDB at that point is empty and ATS is disabled (if available),
//      all accesses will fault and be cancelled rather than successfully
//      translate to physical memory.
//
// =============================================================================

#define UVM_VA_SPACE_MM_SHUTDOWN_DELAY_MAX_MS 100

NV_STATUS uvm_va_space_mm_register(uvm_va_space_t *va_space)
{
    NV_STATUS status = NV_OK;
    uvm_va_space_mm_t *va_space_mm;

    uvm_assert_rwsem_locked_write(&va_space->lock);

    uvm_mutex_lock(&va_space->mm_state.lock);

    va_space_mm = va_space->mm_state.va_space_mm;
    if (va_space_mm == NULL) {
        va_space_mm = uvm_kvmalloc_zero(sizeof(*va_space_mm));
        if (va_space_mm) {
            va_space_mm->va_space = va_space;
            va_space_mm->mm = current->mm;
            va_space_mm->registered_count = 1;
            nv_kref_init(&va_space_mm->kref);
            init_waitqueue_head(&va_space_mm->wait_queue);
            va_space->mm_state.va_space_mm = va_space_mm;
        }
        else {
            status = NV_ERR_NO_MEMORY;
        }
    }
    else {
        UVM_ASSERT(va_space_mm->registered_count > 0);

        // For simplicity, disallow more than one mm per VA space
        if (va_space_mm->mm == current->mm) {
            UVM_ASSERT(!va_space_mm->mm_is_dead);
            ++va_space_mm->registered_count;
            nv_kref_get(&va_space_mm->kref);
        }
        else {
            status = NV_ERR_NOT_SUPPORTED;
        }
    }

    uvm_mutex_unlock(&va_space->mm_state.lock);
    return status;
}

uvm_va_space_mm_t *uvm_va_space_mm_unregister(uvm_va_space_t *va_space)
{
    uvm_va_space_mm_t *va_space_mm;
    bool do_wait = false;

    // We can't hold the VA space lock or mmap_sem while in this function since
    // we're going to wait for retainers to finish below, and retainers will
    // almost certainly need both of those locks.
    uvm_assert_unlocked_order(UVM_LOCK_ORDER_MMAP_SEM);
    uvm_assert_unlocked_order(UVM_LOCK_ORDER_VA_SPACE);

    uvm_mutex_lock(&va_space->mm_state.lock);

    va_space_mm = va_space->mm_state.va_space_mm;
    UVM_ASSERT(va_space_mm);
    UVM_ASSERT(va_space_mm->va_space == va_space);
    UVM_ASSERT(va_space_mm->registered_count > 0);

    if (--va_space_mm->registered_count == 0) {
        // Prevent future retainers from accessing this state, and require new
        // registrations to allocate a new separate one with its own retain
        // count and wait queue. Pending tasks (retainers and mm_shutdown) will
        // still operate on the old pointer.
        va_space->mm_state.va_space_mm = NULL;
        if (va_space_mm->retained_count > 0)
            do_wait = true;
    }

    uvm_mutex_unlock(&va_space->mm_state.lock);

    if (do_wait) {
        // Flush out all pending retainers
        wait_event(va_space_mm->wait_queue, va_space_mm->retained_count == 0);

        // As soon as we return from this function, the caller may free the
        // va_space_mm. Since the wait queue itself is located within the
        // va_space_mm object, we have to wait for the signaling thread in
        // uvm_va_space_mm_release to be completely done operating on this
        // va_space_mm and its wait queue.
        //
        // Do that by taking and dropping the mm_state lock, which is also held
        // by uvm_va_space_mm_release across its signal.
        uvm_mutex_lock(&va_space->mm_state.lock);
        UVM_ASSERT(va_space_mm->registered_count == 0);
        UVM_ASSERT(va_space_mm->retained_count == 0);
        uvm_mutex_unlock(&va_space->mm_state.lock);
    }

    // We haven't dropped the kref, so the caller must complete the operation
    // with uvm_va_space_mm_drop.
    return va_space_mm;
}

static void uvm_va_space_mm_free(nv_kref_t *nv_kref)
{
    uvm_va_space_mm_t *va_space_mm = container_of(nv_kref, uvm_va_space_mm_t, kref);
    UVM_ASSERT(va_space_mm->registered_count == 0);
    UVM_ASSERT(va_space_mm->retained_count == 0);
    UVM_ASSERT(!waitqueue_active(&va_space_mm->wait_queue));
    uvm_kvfree(va_space_mm);
}

void uvm_va_space_mm_drop(uvm_va_space_mm_t *va_space_mm)
{
    nv_kref_put(&va_space_mm->kref, uvm_va_space_mm_free);
}

uvm_va_space_mm_t *uvm_va_space_mm_retain(uvm_va_space_t *va_space)
{
    uvm_va_space_mm_t *va_space_mm;

    uvm_mutex_lock(&va_space->mm_state.lock);

    va_space_mm = va_space->mm_state.va_space_mm;
    if (va_space_mm) {
        UVM_ASSERT(va_space_mm->va_space == va_space);
        UVM_ASSERT(va_space_mm->registered_count > 0);

        if (va_space_mm->mm_is_dead)
            va_space_mm = NULL;
        else
            ++va_space_mm->retained_count;
    }

    uvm_mutex_unlock(&va_space->mm_state.lock);
    return va_space_mm;
}

void uvm_va_space_mm_release(uvm_va_space_mm_t *va_space_mm)
{
    uvm_va_space_t *va_space = va_space_mm->va_space;

    uvm_mutex_lock(&va_space->mm_state.lock);

    UVM_ASSERT(va_space_mm->retained_count > 0);

    // If we're the last retainer, signal any potential waiters
    if (--va_space_mm->retained_count == 0) {
        if (va_space_mm->registered_count == 0) {
            // The VA space's va_space_mm could've been reassigned by a new
            // register call so it might not be NULL, but it can't be our
            // current va_space_mm since it's on its way out.
            UVM_ASSERT(va_space->mm_state.va_space_mm != va_space_mm);
        }

        // Both unregister and mm_shutdown could be waiting on us concurrently,
        // so we have to wake up all waiters. This must be done while holding
        // the mm_state lock, otherwise va_space_mm might be freed from under
        // us. The waiters must take the lock after waking up to guarantee this.
        if (va_space_mm->registered_count == 0 || va_space_mm->mm_is_dead)
            wake_up_all(&va_space_mm->wait_queue);
    }

    // As soon as we drop this lock, va_space_mm could be freed.
    uvm_mutex_unlock(&va_space->mm_state.lock);
}

static void uvm_va_space_mm_shutdown_delay(uvm_va_space_mm_t *va_space_mm)
{
    NvU64 start_time;
    int num_threads;
    bool timed_out = false;

    if (!va_space_mm->test.delay_shutdown)
        return;

    start_time = NV_GETTIME();

    num_threads = atomic_inc_return(&va_space_mm->test.num_mm_shutdown_threads);
    UVM_ASSERT(num_threads > 0);

    if (num_threads == 1) {
        // Wait for another thread to arrive unless we time out
        while (atomic_read(&va_space_mm->test.num_mm_shutdown_threads) == 1) {
            if (NV_GETTIME() - start_time >= 1000*1000*UVM_VA_SPACE_MM_SHUTDOWN_DELAY_MAX_MS) {
                timed_out = true;
                break;
            }
        }

        if (va_space_mm->test.verbose)
            UVM_TEST_PRINT("Multiple threads: %d\n", !timed_out);
    }

    // No need to decrement num_mm_shutdown_threads since this va_space_mm is
    // being shut down.
}

// See the mm teardown block comment at the top of the file.
void uvm_va_space_mm_shutdown(uvm_va_space_mm_t *va_space_mm)
{
    uvm_va_space_t *va_space = va_space_mm->va_space;
    uvm_gpu_va_space_t *gpu_va_space;
    uvm_gpu_t *gpu;
    uvm_processor_mask_t gpus_to_flush;
    LIST_HEAD(deferred_free_list);

    // We need to shut down the VA space on mm teardown, but not on ioctls. We
    // detect this by checking whether current->mm is NULL, since that is always
    // true on mm teardown but never true any ioctl paths. It may be true during
    // file close, but we can tear things down in that case without harm. See
    // the mm teardown block comment at the top of the file.
    if (current->mm != NULL)
        return;

    // Inject a delay for testing if requested
    uvm_va_space_mm_shutdown_delay(va_space_mm);

    // There can be at most two threads here concurrently:
    //
    // 1) Thread A in process teardown of the original process
    //
    // 2) Thread B must be in the implicit file close path of another process
    //    (since current->mm == NULL), having already stopped all GPU accesses
    //    and having called uvm_va_space_mm_unregister.
    //
    // This corresponds to scenario #7 in the mm teardown block comment at the
    // top of the file. We serialize between these threads with the VA space
    // lock, but otherwise don't have any special handling: both threads will
    // execute the full teardown sequence below. Also, remember that the threads
    // won't return to their callers until both threads have returned from this
    // function (mmu_notifier_unregister rules).

    uvm_va_space_down_write(va_space);

    // Prevent future registrations of any kind. We'll be iterating over all
    // GPUs and GPU VA spaces below but taking and dropping the VA space lock.
    // It's ok for other threads to unregister those objects, but not to
    // register new ones.
    //
    // We also need to prevent new channel work from arriving since we're trying
    // to stop memory accesses.
    va_space->disallow_new_registers = true;

    uvm_va_space_downgrade_write_rm(va_space);

    // Stop channels to prevent new accesses and new faults on non-MPS
    uvm_va_space_stop_all_user_channels(va_space);

    uvm_va_space_up_read_rm(va_space);

    // Detach all channels to prevent pending untranslated faults to get to this
    // VA space. This also removes those channels from the VA space and puts
    // them on the deferred free list, so only one thread will do this.
    uvm_processor_mask_zero(&gpus_to_flush);
    uvm_va_space_down_write(va_space);
    uvm_va_space_detach_all_user_channels(va_space, &deferred_free_list);
    uvm_processor_mask_copy(&gpus_to_flush, &va_space->registered_gpus);
    uvm_gpu_retain_mask(&gpus_to_flush);
    uvm_va_space_up_write(va_space);

    // Flush the fault buffer on all GPUs. This will avoid spurious cancels
    // of stale pending translated faults after we set mm_is_dead later.
    for_each_gpu_in_mask(gpu, &gpus_to_flush)
        uvm_gpu_fault_buffer_flush(gpu);
    uvm_gpu_release_mask(&gpus_to_flush);

    // Call nvUvmInterfaceUnsetPageDirectory. This has no effect on non-MPS.
    // Under MPS this guarantees that no new GPU accesses will be made using
    // this mm.
    //
    // We need only one thread to make this call, but two threads in here could
    // race for it, or we could have one thread in here and one in
    // destroy_gpu_va_space. Serialize these by starting in write mode then
    // downgrading to read.
    uvm_va_space_down_write(va_space);
    uvm_va_space_downgrade_write_rm(va_space);
    for_each_gpu_va_space(gpu_va_space, va_space)
        uvm_gpu_va_space_unset_page_dir(gpu_va_space);
    uvm_va_space_up_read_rm(va_space);

    // The above call to uvm_gpu_va_space_unset_page_dir handles the GPU VA
    // spaces which are known to be registered. However, we could've raced with
    // a concurrent uvm_va_space_unregister_gpu_va_space, giving this sequence:
    //
    // unregister_gpu_va_space                  uvm_va_space_mm_shutdown
    //     uvm_va_space_down_write
    //     remove_gpu_va_space
    //     uvm_va_space_up_write
    //                                          uvm_va_space_down_write(va_space);
    //                                          // No GPU VA spaces
    //                                          Unlock, return
    //     uvm_deferred_free_object_list
    //         uvm_gpu_va_space_unset_page_dir
    //
    // We have to be sure that all accesses in this GPU VA space are done before
    // returning, so we have to wait for the other thread to finish its
    // uvm_gpu_va_space_unset_page_dir call.
    //
    // We can be sure that num_pending will eventually go to zero because we've
    // prevented new GPU VA spaces from being registered above.
    wait_event(va_space->gpu_va_space_deferred_free.wait_queue,
               atomic_read(&va_space->gpu_va_space_deferred_free.num_pending) == 0);

    // Now that there won't be any new GPU faults, prevent subsequent retainers
    // from accessing this va_space_mm.
    uvm_mutex_lock(&va_space->mm_state.lock);
    va_space_mm->mm_is_dead = true;
    uvm_mutex_unlock(&va_space->mm_state.lock);

    // Finish channel destroy. This can be done at any point after detach as
    // long as we don't hold the VA space lock.
    uvm_deferred_free_object_list(&deferred_free_list);

    // Flush out all pending retainers
    wait_event(va_space_mm->wait_queue, va_space_mm->retained_count == 0);

    // See the comment on wait_event in uvm_va_space_mm_unregister on why taking
    // this lock is necessary.
    uvm_mutex_lock(&va_space->mm_state.lock);
    UVM_ASSERT(va_space_mm->retained_count == 0);

    // As soon as we drop this lock, va_space_mm could be freed.
    uvm_mutex_unlock(&va_space->mm_state.lock);
}

static NV_STATUS mm_read64(struct mm_struct *mm, NvU64 addr, NvU64 *val)
{
    long ret;
    int write = 0, force = 0;
    struct page *page;
    NvU64 *mapping;

    UVM_ASSERT(IS_ALIGNED(addr, sizeof(val)));

    uvm_down_read_mmap_sem(&mm->mmap_sem);
    ret = NV_GET_USER_PAGES_REMOTE(NULL, mm, (unsigned long)addr, 1, write, force, &page, NULL);
    uvm_up_read_mmap_sem(&mm->mmap_sem);

    if (ret < 0)
        return errno_to_nv_status(ret);

    UVM_ASSERT(ret == 1);

    mapping = (NvU64 *)((char *)kmap(page) + (addr % PAGE_SIZE));
    *val = *mapping;
    kunmap(page);
    put_page(page);

    return NV_OK;
}

NV_STATUS uvm8_test_va_space_mm_retain(UVM_TEST_VA_SPACE_MM_RETAIN_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = NULL;
    uvm_va_space_mm_t *va_space_mm = NULL;
    NV_STATUS status = NV_OK;

    if (!IS_ALIGNED(params->addr, sizeof(params->val_before)))
        return NV_ERR_INVALID_ARGUMENT;

    uvm_mutex_lock(&g_uvm_global.va_spaces.lock);

    list_for_each_entry(va_space, &g_uvm_global.va_spaces.list, list_node) {
        if ((uintptr_t)va_space == params->va_space_ptr) {
            va_space_mm = uvm_va_space_mm_retain(va_space);
            break;
        }
    }

    uvm_mutex_unlock(&g_uvm_global.va_spaces.lock);

    if ((uintptr_t)va_space != params->va_space_ptr)
        return NV_ERR_MISSING_TABLE_ENTRY;

    if (!va_space_mm)
        return NV_ERR_PAGE_TABLE_NOT_AVAIL;

    status = mm_read64(va_space_mm->mm, params->addr, &params->val_before);

    if (status == NV_OK && params->sleep_us) {
        usleep_range(params->sleep_us, params->sleep_us + 1000);
        status = mm_read64(va_space_mm->mm, params->addr, &params->val_after);
    }

    uvm_va_space_mm_release(va_space_mm);
    return status;
}

NV_STATUS uvm8_test_va_space_mm_delay_shutdown(UVM_TEST_VA_SPACE_MM_DELAY_SHUTDOWN_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_va_space_mm_t *va_space_mm;
    NV_STATUS status = NV_ERR_PAGE_TABLE_NOT_AVAIL;

    uvm_va_space_down_write(va_space);

    va_space_mm = uvm_va_space_mm_retain(va_space);
    if (va_space_mm) {
        va_space_mm->test.delay_shutdown = true;
        va_space_mm->test.verbose = params->verbose;
        uvm_va_space_mm_release(va_space_mm);
        status = NV_OK;
    }

    uvm_va_space_up_write(va_space);

    return status;
}
