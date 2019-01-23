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

#ifndef __UVM8_VA_SPACE_H__
#define __UVM8_VA_SPACE_H__

#include "uvm8_processors.h"
#include "uvm8_global.h"
#include "uvm8_gpu.h"
#include "uvm8_range_tree.h"
#include "uvm8_range_group.h"
#include "uvm8_forward_decl.h"
#include "uvm8_mmu.h"
#include "uvm_linux.h"
#include "nv-kref.h"
#include "uvm8_perf_events.h"
#include "uvm8_perf_module.h"
#include "uvm8_va_block_types.h"
#include "uvm8_va_block.h"
#include "uvm8_hmm.h"

// uvm_deferred_free_object provides a mechanism for building and later freeing
// a list of objects which are owned by a VA space, but can't be freed while the
// VA space lock is held.

typedef enum
{
    UVM_DEFERRED_FREE_OBJECT_TYPE_CHANNEL,
    UVM_DEFERRED_FREE_OBJECT_GPU_VA_SPACE,
    UVM_DEFERRED_FREE_OBJECT_TYPE_EXTERNAL_ALLOCATION,
    UVM_DEFERRED_FREE_OBJECT_TYPE_COUNT
} uvm_deferred_free_object_type_t;

typedef struct
{
    uvm_deferred_free_object_type_t type;
    struct list_head list_node;
} uvm_deferred_free_object_t;

static void uvm_deferred_free_object_add(struct list_head *list,
                                         uvm_deferred_free_object_t *object,
                                         uvm_deferred_free_object_type_t type)
{
    object->type = type;
    list_add_tail(&object->list_node, list);
}

// Walks the list of pending objects and frees each one as appropriate to its
// type.
//
// LOCKING: May take the GPU isr_lock and the RM locks.
void uvm_deferred_free_object_list(struct list_head *deferred_free_list);

typedef enum
{
    // The GPU VA space has been initialized but not yet inserted into the
    // parent VA space.
    UVM_GPU_VA_SPACE_STATE_INIT = 0,

    // The GPU VA space is active in the VA space.
    UVM_GPU_VA_SPACE_STATE_ACTIVE,

    // The GPU VA space is no longer active in the VA space. This state can be
    // observed when threads retain the gpu_va_space then drop the VA space
    // lock. After re-taking the VA space lock, the state must be inspected to
    // see if another thread unregistered the gpu_va_space in the meantime.
    UVM_GPU_VA_SPACE_STATE_DEAD,

    UVM_GPU_VA_SPACE_STATE_COUNT
} uvm_gpu_va_space_state_t;

struct uvm_gpu_va_space_struct
{
    // Parent pointers
    uvm_va_space_t *va_space;
    uvm_gpu_t *gpu;

    uvm_gpu_va_space_state_t state;

    // Handle to the duped GPU VA space
    // to be used for all further GPU VA space related UVM-RM interactions.
    uvmGpuAddressSpaceHandle duped_gpu_va_space;
    bool did_set_page_directory;

    uvm_page_tree_t page_tables;

    // List of all uvm_user_channel_t's under this GPU VA space
    struct list_head registered_channels;

    // List of all uvm_va_range_t's under this GPU VA space with type ==
    // UVM_VA_RANGE_TYPE_CHANNEL. Used at channel registration time to find
    // shareable VA ranges without having to iterate through all VA ranges in
    // the VA space.
    struct list_head channel_va_ranges;

    // Boolean which is 1 if no new channel registration is allowed. This is set
    // when all the channels under the GPU VA space have been stopped to prevent
    // new ones from entering after we drop the VA space lock. It is an atomic_t
    // because multiple threads may set it to 1 concurrently.
    atomic_t disallow_new_channels;

    // On VMA destruction, the fault buffer needs to be flushed for all the GPUs
    // registered in the VA space to avoid leaving stale entries of the VA range
    // that is going to be destroyed. Otherwise, these fault entries can be
    // attributed to new VA ranges reallocated at the same addresses. However,
    // uvm_vm_close is called with mm->mmap_sem taken and we cannot take the ISR
    // lock. Therefore, we use a flag no notify the GPU fault handler that the
    // fault buffer needs to be flushed, before servicing the faults that belong
    // to the va_space.
    bool needs_fault_buffer_flush;

    // Whether teardown needs to call uvm_va_space_mm_unregister. Used to handle
    // error cases of tearing down partially-created GPU VA spaces.
    bool did_va_space_mm_register;

    // Node for the deferred free list where this GPU VA space is stored upon
    // being unregistered.
    uvm_deferred_free_object_t deferred_free;

    // Reference count for this gpu_va_space. This only protects the memory
    // object itself, for use in cases when the gpu_va_space needs to be
    // accessed across dropping and re-acquiring the VA space lock.
    nv_kref_t kref;

    struct
    {
        // Each GPU VA space can have ATS enabled or disabled in its hardware
        // state. This is controlled by user space when it allocates that GPU VA
        // space object from RM. This flag indicates the mode user space
        // requested when allocating this GPU VA space.
        bool enabled;

#if defined(NV_PNV_NPU2_INIT_CONTEXT_PRESENT)
        struct npu_context *npu_context;
#endif

        // Association between the mm and the VA space. All GPU VA spaces in a
        // VA space have the same ats_mm pointer. It is valid while the
        // npu_context is valid.
        uvm_ats_ibm_mm_t *ats_mm;
    } ats;
};

struct uvm_va_space_struct
{
    // Mask of gpus registered with the va space
    uvm_processor_mask_t registered_gpus;

    // Mask of processors registered with the va space that support replayable faults
    uvm_processor_mask_t faultable_processors;

    // Semaphore protecting the state of the va space
    uvm_rw_semaphore_t lock;

    // Lock taken prior to taking the VA space lock in write mode, or prior to
    // taking the VA space lock in read mode on a path which will call in RM.
    // See UVM_LOCK_ORDER_VA_SPACE_SERIALIZE_WRITERS in uvm8_lock.h.
    uvm_mutex_t serialize_writers_lock;

    // Lock taken to serialize down_reads on the VA space lock with up_writes in
    // other threads. See
    // UVM_LOCK_ORDER_VA_SPACE_READ_ACQUIRE_WRITE_RELEASE_LOCK in uvm8_lock.h.
    uvm_mutex_t read_acquire_write_release_lock;

    // Tree of uvm_va_range_t's
    uvm_range_tree_t va_range_tree;

    // Kernel mapping structure passed to unmap_mapping range to unmap CPU PTEs
    // in this process.
    struct address_space mapping;

    // Storage in g_uvm_global.va_spaces.list
    struct list_head list_node;

    // Monotonically increasing counter for range groups IDs
    atomic64_t range_group_id_counter;

    // Range groups
    struct radix_tree_root range_groups;
    uvm_range_tree_t range_group_ranges;

    // Peer to peer table
    // A bitmask of peer to peer pairs enabled in this va_space
    // indexed by a peer_table_index returned by uvm_gpu_peer_table_index().
    DECLARE_BITMAP(enabled_peers, UVM_MAX_UNIQUE_GPU_PAIRS);

    // Temporary copy of the above state used to avoid allocation during VA
    // space destroy.
    DECLARE_BITMAP(enabled_peers_teardown, UVM_MAX_UNIQUE_GPU_PAIRS);

    // Interpreting these processor masks:
    //      uvm_processor_mask_test(foo[A], B)
    // ...should be read as "test if A foo B." For example:
    //      uvm_processor_mask_test(accessible_from[B], A)
    // means "test if B is accessible_from A."

    // Pre-computed masks that contain, for each processor, a mask of processors
    // which that processor can directly access. In other words, this will test
    // whether A has direct access to B:
    //      uvm_processor_mask_test(can_access[A], B)
    uvm_processor_mask_t can_access[UVM_MAX_PROCESSORS];

    // Pre-computed masks that contain, for each processor memory, a mask with
    // the processors that have direct access enabled to its memory. This is the
    // opposite direction as can_access. In other words, this will test whether
    // A has direct access to B:
    //      uvm_processor_mask_test(accessible_from[B], A)
    uvm_processor_mask_t accessible_from[UVM_MAX_PROCESSORS];

    // Pre-computed masks that contain, for each processor memory, a mask with
    // the processors that can directly copy to and from its memory. This is
    // almost the same as accessible_from masks, but also requires peer identity
    // mappings to be supported for peer access.
    uvm_processor_mask_t can_copy_from[UVM_MAX_PROCESSORS];

    // Pre-computed masks that contain, for each processor, a mask of processors
    // to which that processor has NVLINK access. In other words, this will test
    // whether A has NVLINK access to B:
    //      uvm_processor_mask_test(has_nvlink[A], B)
    // This is a subset of can_access.
    uvm_processor_mask_t has_nvlink[UVM_MAX_PROCESSORS];

    // Pre-computed masks that contain, for each processor memory, a mask with
    // the processors that have direct access to its memory and native support
    // for atomics in HW. This is a subset of accessible_from.
    uvm_processor_mask_t has_native_atomics[UVM_MAX_PROCESSORS];

    // Pre-computed masks that contain, for each processor memory, a mask with
    // the processors that are indirect peers. Indirect peers can access each
    // other's memory like regular peers, but with additional latency and/or bw
    // penalty.
    uvm_processor_mask_t indirect_peers[UVM_MAX_PROCESSORS];

    // Mask of gpu_va_spaces registered with the va space
    // indexed by gpu->id
    uvm_processor_mask_t registered_gpu_va_spaces;

    // Mask of GPUs which have temporarily dropped the VA space lock mid-
    // unregister. Used to make other paths return an error rather than
    // corrupting state.
    uvm_processor_mask_t gpu_unregister_in_progress;

    // Mask of processors that are participating in system-wide atomics
    uvm_processor_mask_t system_wide_atomics_enabled_processors;

    // Array of GPU VA spaces
    uvm_gpu_va_space_t *gpu_va_spaces[UVM_MAX_GPUS];

    // Tracking of GPU VA spaces which have dropped the VA space lock and are
    // pending destruction. uvm_va_space_mm_shutdown has to wait for those
    // destroy operations to be completely done.
    struct
    {
        atomic_t num_pending;
        wait_queue_head_t wait_queue;
    } gpu_va_space_deferred_free;

    // Per-va_space event notification information for performance heuristics
    uvm_perf_va_space_events_t perf_events;

    uvm_perf_module_data_desc_t perf_modules_data[UVM_PERF_MODULE_TYPE_COUNT];

    // Array of modules that are loaded in the va_space, indexed by module type
    uvm_perf_module_t *perf_modules[UVM_PERF_MODULE_TYPE_COUNT];

    // Lists of counters listening for events on this VA space
    // Protected by lock
    struct
    {
        bool enabled;

        uvm_rw_semaphore_t lock;

        // Lists of counters listening for events on this VA space
        struct list_head counters[UVM_TOTAL_COUNTERS];
        struct list_head queues[UvmEventNumTypesAll];

        // Node for this va_space in global subscribers list
        struct list_head node;
    } tools;

    // Boolean which is 1 if all user channels have been already stopped. This
    // is an atomic_t because multiple threads may call
    // uvm_va_space_stop_all_user_channels concurrently.
    atomic_t user_channels_stopped;

    // Prevent future registrations of any kind (GPU, GPU VA space, channel).
    // This is used when the associated va_space_mm is torn down, which has to
    // prevent any new work from being started in this VA space.
    bool disallow_new_registers;

    bool user_channel_stops_are_immediate;

    // Block context used for GPU unmap operations so that allocation is not
    // required on the teardown path. This can only be used while the VA space
    // lock is held in write mode. Access using uvm_va_space_block_context().
    uvm_va_block_context_t va_block_context;

    // UVM_INITIALIZE has been called
    bool initialized;
    NvU64 initialization_flags;

    bool test_page_prefetch_enabled;

    struct
    {
        // Lock protecting the va_space_mm pointer assignment.
        uvm_mutex_t lock;

        // The mm currently associated with this VA space. Most callers
        // shouldn't access this directly, but should instead use
        // uvm_va_space_mm_retain/uvm_va_space_mm_release.
        uvm_va_space_mm_t *va_space_mm;

        // Lock held over uvm_ats_ibm_register_gpu_va_space and taken within
        // uvm_ats_ibm_unregister_gpu_va_space. See the block comment in
        // uvm_ats_ibm_unregister_gpu_va_space.
        uvm_mutex_t ats_reg_unreg_lock;
    } mm_state;

#if UVM_IS_CONFIG_HMM()
    // HMM information about this VA space.
    uvm_hmm_va_space_t hmm_va_space;
#endif
};

NV_STATUS uvm_va_space_create(struct inode *inode, struct file *filp);
void uvm_va_space_destroy(struct file *filp);

// All VA space locking should be done with these wrappers. They're macros so
// lock assertions are attributed to line numbers correctly.

#define uvm_va_space_down_write(__va_space)                             \
    do {                                                                \
        uvm_mutex_lock(&(__va_space)->serialize_writers_lock);          \
        uvm_mutex_lock(&(__va_space)->read_acquire_write_release_lock); \
        uvm_down_write(&(__va_space)->lock);                            \
    } while (0)

#define uvm_va_space_up_write(__va_space)                                   \
    do {                                                                    \
        uvm_up_write(&(__va_space)->lock);                                  \
        uvm_mutex_unlock(&(__va_space)->read_acquire_write_release_lock);   \
        uvm_mutex_unlock(&(__va_space)->serialize_writers_lock);            \
    } while (0)

#define uvm_va_space_downgrade_write(__va_space)                                        \
    do {                                                                                \
        uvm_downgrade_write(&(__va_space)->lock);                                       \
        uvm_mutex_unlock_out_of_order(&(__va_space)->read_acquire_write_release_lock);  \
        uvm_mutex_unlock_out_of_order(&(__va_space)->serialize_writers_lock);           \
    } while (0)

// Call this when holding the VA space lock for write in order to downgrade to
// read on a path which also needs to make RM calls.
#define uvm_va_space_downgrade_write_rm(__va_space)                                     \
    do {                                                                                \
        uvm_assert_mutex_locked(&(__va_space)->serialize_writers_lock);                 \
        uvm_downgrade_write(&(__va_space)->lock);                                       \
        uvm_mutex_unlock_out_of_order(&(__va_space)->read_acquire_write_release_lock);  \
    } while (0)

#define uvm_va_space_down_read(__va_space)                                              \
    do {                                                                                \
        uvm_mutex_lock(&(__va_space)->read_acquire_write_release_lock);                 \
        uvm_down_read(&(__va_space)->lock);                                             \
        uvm_mutex_unlock_out_of_order(&(__va_space)->read_acquire_write_release_lock);  \
    } while (0)

// Call this if RM calls need to be made while holding the VA space lock in read
// mode. Note that taking read_acquire_write_release_lock is unnecessary since
// the down_read is serialized with another thread's up_write by the
// serialize_writers_lock.
#define uvm_va_space_down_read_rm(__va_space)                           \
    do {                                                                \
        uvm_mutex_lock(&(__va_space)->serialize_writers_lock);          \
        uvm_down_read(&(__va_space)->lock);                             \
    } while (0)

#define uvm_va_space_up_read(__va_space) uvm_up_read(&(__va_space)->lock)

#define uvm_va_space_up_read_rm(__va_space)                             \
    do {                                                                \
        uvm_up_read(&(__va_space)->lock);                               \
        uvm_mutex_unlock(&(__va_space)->serialize_writers_lock);        \
    } while (0)

// Get a registered gpu by uuid. This restricts the search for GPUs, to those that
// have been registered with a va_space. This returns NULL if the GPU is not present, or not
// registered with the va_space.
uvm_gpu_t *uvm_va_space_get_gpu_by_uuid(uvm_va_space_t *va_space, const NvProcessorUuid *gpu_uuid);

// Like uvm_va_space_get_gpu_by_uuid, but also returns NULL if the GPU does
// not have a GPU VA space registered in the UVM va_space.
uvm_gpu_t *uvm_va_space_get_gpu_by_uuid_with_gpu_va_space(uvm_va_space_t *va_space, const NvProcessorUuid *gpu_uuid);

// Returns whether read-duplication is supported
// If gpu is NULL, returns the current state.
// otherwise, it retuns what the result would be once the gpu's va space is added or removed
// (by inverting the gpu's current state)
bool uvm_va_space_can_read_duplicate(uvm_va_space_t *va_space, uvm_gpu_t *changing_gpu);

// Register a gpu in the va space
// Note that each gpu can be only registered once in a va space
//
// This call returns whether the GPU memory is a NUMA node in the kernel and the
// corresponding node id.
NV_STATUS uvm_va_space_register_gpu(uvm_va_space_t *va_space,
                                    const NvProcessorUuid *gpu_uuid,
                                    NvBool *numa_enabled,
                                    NvS32 *numa_node_id);

// Unregister a gpu from the va space
NV_STATUS uvm_va_space_unregister_gpu(uvm_va_space_t *va_space, const NvProcessorUuid *gpu_uuid);

// Registers a GPU VA space with the UVM VA space.
NV_STATUS uvm_va_space_register_gpu_va_space(uvm_va_space_t *va_space,
                                             uvm_rm_user_object_t *user_rm_va_space,
                                             const NvProcessorUuid *gpu_uuid);

// Unregisters a GPU VA space from the UVM VA space.
NV_STATUS uvm_va_space_unregister_gpu_va_space(uvm_va_space_t *va_space, const NvProcessorUuid *gpu_uuid);

// Stop all user channels
//
// This function sets a flag in the VA space indicating that all the channels
// have been already stopped and should only be used when no new user channels
// can be registered.
//
// LOCKING: The VA space lock must be held in read mode, not write.
void uvm_va_space_stop_all_user_channels(uvm_va_space_t *va_space);

// Calls uvm_user_channel_detach on all user channels in a VA space.
//
// The detached channels are added to the input list. The caller is expected to
// drop the VA space lock and call uvm_deferred_free_object_list to complete the
// destroy operation.
//
// LOCKING: The owning VA space must be locked in write mode.
void uvm_va_space_detach_all_user_channels(uvm_va_space_t *va_space, struct list_head *deferred_free_list);

// Returns whether peer access between these two GPUs has been enabled in this
// VA space. Both GPUs must be registered in the VA space.
bool uvm_va_space_peer_enabled(uvm_va_space_t *va_space, uvm_gpu_t *gpu1, uvm_gpu_t *gpu2);

static uvm_va_space_t *uvm_va_space_get(struct file *filp)
{
    UVM_ASSERT_MSG(filp->private_data != NULL, "filp: 0x%llx", (NvU64)filp);

    return (uvm_va_space_t *)filp->private_data;
}

static uvm_va_block_context_t *uvm_va_space_block_context(uvm_va_space_t *va_space)
{
    uvm_assert_rwsem_locked_write(&va_space->lock);

    uvm_va_block_context_init(&va_space->va_block_context);

    return &va_space->va_block_context;
}

// Retains the GPU VA space memory object. destroy_gpu_va_space and
// uvm_gpu_va_space_release drop the count. This is used to keep the GPU VA
// space object allocated when dropping and re-taking the VA space lock. If
// another thread called remove_gpu_va_space in the meantime,
// gpu_va_space->state will be UVM_GPU_VA_SPACE_STATE_DEAD.
static inline void uvm_gpu_va_space_retain(uvm_gpu_va_space_t *gpu_va_space)
{
    nv_kref_get(&gpu_va_space->kref);
}

// This only frees the GPU VA space object itself, so it must have been removed
// from its VA space and destroyed prior to the final release.
void uvm_gpu_va_space_release(uvm_gpu_va_space_t *gpu_va_space);

// Wrapper for nvUvmInterfaceUnsetPageDirectory
void uvm_gpu_va_space_unset_page_dir(uvm_gpu_va_space_t *gpu_va_space);

static uvm_gpu_va_space_state_t uvm_gpu_va_space_state(uvm_gpu_va_space_t *gpu_va_space)
{
    UVM_ASSERT(gpu_va_space->gpu);

    switch (gpu_va_space->state) {
        case UVM_GPU_VA_SPACE_STATE_INIT:
            UVM_ASSERT(!gpu_va_space->va_space);
            break;

        case UVM_GPU_VA_SPACE_STATE_ACTIVE:
        case UVM_GPU_VA_SPACE_STATE_DEAD:
            UVM_ASSERT(gpu_va_space->va_space);
            break;

        default:
            UVM_ASSERT_MSG(0, "Invalid state: %u\n", gpu_va_space->state);
            break;
    }

    return gpu_va_space->state;
}

static uvm_gpu_va_space_t *uvm_gpu_va_space_get(uvm_va_space_t *va_space, uvm_gpu_t *gpu)
{
    uvm_gpu_va_space_t *gpu_va_space;

    uvm_assert_rwsem_locked(&va_space->lock);

    if (!gpu || !uvm_processor_mask_test(&va_space->registered_gpu_va_spaces, gpu->id))
        return NULL;

    gpu_va_space = va_space->gpu_va_spaces[uvm_gpu_index(gpu->id)];
    UVM_ASSERT(uvm_gpu_va_space_state(gpu_va_space) == UVM_GPU_VA_SPACE_STATE_ACTIVE);
    UVM_ASSERT(gpu_va_space->va_space == va_space);
    UVM_ASSERT(gpu_va_space->gpu == gpu);
    return gpu_va_space;
}

#define for_each_gpu_va_space(__gpu_va_space, __va_space)                                               \
    for (__gpu_va_space = uvm_gpu_va_space_get(                                                         \
                              __va_space,                                                               \
                              uvm_processor_mask_find_first_gpu(&__va_space->registered_gpu_va_spaces)  \
                          );                                                                            \
         __gpu_va_space;                                                                                \
         __gpu_va_space = uvm_gpu_va_space_get(                                                         \
                              __va_space,                                                               \
                              uvm_processor_mask_find_next_gpu(&__va_space->registered_gpu_va_spaces,   \
                                                               __gpu_va_space->gpu)                     \
                          )                                                                             \
        )

// Return the processor in the candidates mask that is "closest" to src, or
// UVM_MAX_PROCESSORS if candidates is empty. The order is:
// - src itself
// - Direct NVLINK peers (src is CPU or GPU)
// - Indirect NVLINK peers (src is GPU)
// - PCIe peers (src is GPU)
// - CPU (src is GPU)
// - Arbitrary selection
uvm_processor_id_t uvm_processor_mask_find_closest_id(uvm_va_space_t *va_space,
                                                      const uvm_processor_mask_t *candidates,
                                                      uvm_processor_id_t src);

// Iterate over each ID in mask in order of proximity to src. This is
// destructive to mask.
#define for_each_closest_id(id, mask, src, va_space)                    \
    for (id = uvm_processor_mask_find_closest_id(va_space, mask, src);  \
         id != UVM_MAX_PROCESSORS;                                     \
         uvm_processor_mask_clear(mask, id), id = uvm_processor_mask_find_closest_id(va_space, mask, src))

// Obtain the user channel with the given instance_ptr. This is used during
// non-replayable fault service. This function needs to be called with the va
// space lock held in order to prevent channels from being removed.
uvm_user_channel_t *uvm_gpu_va_space_get_user_channel(uvm_gpu_va_space_t *gpu_va_space,
                                                      uvm_gpu_phys_address_t instance_ptr);

NV_STATUS uvm8_test_enable_nvlink_peer_access(UVM_TEST_ENABLE_NVLINK_PEER_ACCESS_PARAMS *params, struct file *filp);
NV_STATUS uvm8_test_disable_nvlink_peer_access(UVM_TEST_DISABLE_NVLINK_PEER_ACCESS_PARAMS *params, struct file *filp);

#endif // __UVM8_VA_SPACE_H__
