/*******************************************************************************
    Copyright (c) 2016 NVIDIA Corporation

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
    LIABILITY, WHETHER IN AN hint OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

#include "uvm8_perf_events.h"
#include "uvm8_perf_module.h"
#include "uvm8_perf_thrashing.h"
#include "uvm8_perf_utils.h"
#include "uvm8_va_block.h"
#include "uvm8_va_range.h"
#include "uvm8_kvmalloc.h"
#include "uvm8_tools.h"

// Number of bits for page-granularity time stamps. Currently we ignore the first 6 bits
// of the timestamp (i.e. we have 64ns resolution, which is good enough)
#define PAGE_THRASHING_LAST_TIME_STAMP_BITS 58
#define PAGE_THRASHING_NUM_EVENTS_BITS      3

#define PAGE_THRASHING_THROTTLING_END_TIME_STAMP_BITS 58
#define PAGE_THRASHING_THROTTLING_COUNT_BITS          8

// Per-page thrashing detection structure.
typedef struct
{
    struct
    {
        // Last time stamp when a thrashing-related event was recorded
        NvU64                        last_time_stamp : PAGE_THRASHING_LAST_TIME_STAMP_BITS;

        bool                    has_migration_events : 1;

        bool                   has_revocation_events : 1;

        // Number of consecutive "thrashing" events (within the configured
        // thrashing lapse)
        NvU8                    num_thrashing_events : PAGE_THRASHING_NUM_EVENTS_BITS;

        bool                                  pinned : 1;
    };

    struct
    {
        // Deadline for throttled processors to wake up
        NvU64              throttling_end_time_stamp : PAGE_THRASHING_THROTTLING_END_TIME_STAMP_BITS;

        // Number of times a processor has been throttled. This is used to
        // determine when the page needs to get pinned. After getting pinned
        // this field is always 0.
        NvU8                        throttling_count : PAGE_THRASHING_THROTTLING_COUNT_BITS;
    };

    // Processors accessing this page
    uvm_processor_mask_t                  processors;

    // Processors that have been throttled. This must be a subset of processors
    uvm_processor_mask_t        throttled_processors;

    struct
    {
        // Memory residency for the page when in pinning phase
        uvm_processor_id_t          pinned_residency : 16;

        // Processor not to be throttled in the current throttling period
        uvm_processor_id_t do_not_throttle_processor : 16;
    };
} page_thrashing_info_t;

// Per-VA block thrashing detection structure. This state is protected by the
// VA block lock.
typedef struct
{
    page_thrashing_info_t                     *pages;

    NvU16                        num_thrashing_pages;

    NvU8                       thrashing_reset_count;

    uvm_processor_id_t                last_processor;

    NvU64                            last_time_stamp;

    NvU64                  last_thrashing_time_stamp;

    // Stats
    NvU32                           throttling_count;

    uvm_page_mask_t                  thrashing_pages;

    struct
    {
        NvU32                                  count;

        uvm_page_mask_t                         mask;

        // List of pinned pages. This list is only used if the pinning timeout
        // is not 0.
        struct list_head                        list;
    } pinned_pages;
} block_thrashing_info_t;

// Descriptor for a page that has been pinned due to thrashing. This structure
// is only used if the pinning timeout is not 0.
typedef struct
{
    uvm_va_block_t                         *va_block;

    // Page index within va_block
    uvm_page_index_t                      page_index;

    // Absolute timestamp after which the page will be unpinned
    NvU64                                   deadline;

    // Entry in the per-VA Space list of pinned pages. See
    // va_space_thrashing_info_t::pinned_pages::list.
    struct list_head             va_space_list_entry;

    // Entry in the per-VA Block list of pinned pages. See
    // block_thrashing_info_t::pinned_pages::list.
    struct list_head             va_block_list_entry;
} pinned_page_t;

// Per-VA space data structures and policy configuration
typedef struct
{
    // Per-VA space accounting of pinned pages that is used to speculatively
    // unpin pages after the configured timeout. This struct is only used if
    // the pinning timeout is not 0.
    struct
    {
        // Work descriptor that is executed asynchronously by a helper thread
        struct delayed_work                    dwork;

        // List of pinned pages. They are (mostly) ordered by unpin deadline.
        // New entries are inserted blindly at the tail since the expectation
        // is that they will have the largest deadline value. However, given
        // the drift between when multiple threads query their timestamps and
        // add those pages to the list under the lock, it might not be
        // strictly ordered. But this is OK since the difference will be very
        // small and they will be eventually removed from the list.
        //
        // Entries are removed when they reach the deadline by the function
        // configured in dwork. This list is protected by lock.
        struct list_head                        list;

        uvm_spinlock_t                          lock;

        uvm_va_block_context_t      va_block_context;

        // Flag used to avoid scheduling delayed unpinning operations after
        // uvm_perf_thrashing_stop has been called.
        bool                    in_va_space_teardown;
    } pinned_pages;

    struct
    {
        bool                                  enable;

        unsigned                           threshold;

        unsigned                       pin_threshold;

        NvU64                               lapse_ns;

        NvU64                                 nap_ns;

        NvU64                               epoch_ns;

        unsigned                          max_resets;

        NvU64                                 pin_ns;
    } params;

    uvm_va_space_t                         *va_space;
} va_space_thrashing_info_t;

// Global caches for the per-VA block thrashing detection structures
static struct kmem_cache *g_va_block_thrashing_info_cache __read_mostly;
static struct kmem_cache *g_pinned_page_cache __read_mostly;

//
// Tunables for thrashing detection/prevention (configurable via module parameters)
//

// Enable/disable thrashing performance heuristics
static unsigned uvm_perf_thrashing_enable = 1;

#define UVM_PERF_THRASHING_THRESHOLD_DEFAULT 3
#define UVM_PERF_THRASHING_THRESHOLD_MAX     ((1 << PAGE_THRASHING_NUM_EVENTS_BITS) - 1)

// Number of consecutive thrashing events to initiate thrashing prevention
//
// Maximum value is UVM_PERF_THRASHING_THRESHOLD_MAX
static unsigned uvm_perf_thrashing_threshold = UVM_PERF_THRASHING_THRESHOLD_DEFAULT;

#define UVM_PERF_THRASHING_PIN_THRESHOLD_DEFAULT 10
#define UVM_PERF_THRASHING_PIN_THRESHOLD_MAX     ((1 << PAGE_THRASHING_THROTTLING_COUNT_BITS) - 1)

// Number of consecutive throttling operations before trying to map remotely
//
// Maximum value is UVM_PERF_THRASHING_PIN_THRESHOLD_MAX
static unsigned uvm_perf_thrashing_pin_threshold = UVM_PERF_THRASHING_PIN_THRESHOLD_DEFAULT;

// TODO: Bug 1768615: [uvm8] Automatically tune default values for thrashing
// detection/prevention parameters
#define UVM_PERF_THRASHING_LAPSE_USEC_DEFAULT 250

// Lapse of time in microseconds that determines if two consecutive events on
// the same page can be considered thrashing
static unsigned uvm_perf_thrashing_lapse_usec = UVM_PERF_THRASHING_LAPSE_USEC_DEFAULT;

#define UVM_PERF_THRASHING_NAP_USEC_DEFAULT (UVM_PERF_THRASHING_LAPSE_USEC_DEFAULT * 2)
#define UVM_PERF_THRASHING_NAP_USEC_MAX     (250*1000)

// Time that the processor being throttled is forbidden to work on the thrashing
// page. Time is counted in microseconds
static unsigned uvm_perf_thrashing_nap_usec   = UVM_PERF_THRASHING_NAP_USEC_DEFAULT;

// Time lapse after which we consider thrashing is no longer happening. Time is
// counted in milliseconds
#define UVM_PERF_THRASHING_EPOCH_MSEC_DEFAULT 1000

static unsigned uvm_perf_thrashing_epoch_msec = UVM_PERF_THRASHING_EPOCH_MSEC_DEFAULT;

// Number of times a VA block can be reset back to non-thrashing. This
// mechanism tries to avoid performing optimizations on a block that periodically
// causes thrashing
#define UVM_PERF_THRASHING_MAX_RESETS_DEFAULT 4

static unsigned uvm_perf_thrashing_max_resets = UVM_PERF_THRASHING_MAX_RESETS_DEFAULT;

// When pages are pinned and the rest of thrashing processors are mapped
// remotely we lose track of who is accessing the page for the rest of
// program execution. This can lead to tremendous performance loss if the page
// is not thrashing anymore and it is always being accessed remotely.
// In order to avoid that scenario, we use a timer that unpins memory after
// some time (150ms by default). We use a per-VA space list of pinned pages,
// sorted by the deadline at which it will be unmapped from remote processors.
// Therefore, next remote access will trigger a fault that will migrate the
// page.
//
// Lapse of time in milliseconds for which a page remains pinned. 0 means that
// it is pinned forever.
#define UVM_PERF_THRASHING_PIN_MSEC_DEFAULT 150

static unsigned uvm_perf_thrashing_pin_msec = UVM_PERF_THRASHING_PIN_MSEC_DEFAULT;

// Module parameters for the tunables
module_param(uvm_perf_thrashing_enable, uint, S_IRUGO);
module_param(uvm_perf_thrashing_threshold, uint, S_IRUGO);
module_param(uvm_perf_thrashing_pin_threshold, uint, S_IRUGO);
module_param(uvm_perf_thrashing_lapse_usec, uint, S_IRUGO);
module_param(uvm_perf_thrashing_nap_usec, uint, S_IRUGO);
module_param(uvm_perf_thrashing_epoch_msec, uint, S_IRUGO);
module_param(uvm_perf_thrashing_max_resets, uint, S_IRUGO);
module_param(uvm_perf_thrashing_pin_msec, uint, S_IRUGO);

// See map_remote_on_atomic_fault uvm8_va_block.c
unsigned uvm_perf_map_remote_on_native_atomics_fault = 0;
module_param(uvm_perf_map_remote_on_native_atomics_fault, uint, S_IRUGO);

// Global post-processed values of the module parameters. They can be overriden
// per VA-space.
static bool g_uvm_perf_thrashing_enable;
static unsigned g_uvm_perf_thrashing_threshold;
static unsigned g_uvm_perf_thrashing_pin_threshold;
static NvU64 g_uvm_perf_thrashing_lapse_ns;
static NvU64 g_uvm_perf_thrashing_nap_ns;
static NvU64 g_uvm_perf_thrashing_epoch_ns;
static unsigned g_uvm_perf_thrashing_max_resets;
static NvU64 g_uvm_perf_thrashing_pin_ns;

// Helpers to get/set the time stamp
static NvU64 page_thrashing_get_time_stamp(page_thrashing_info_t *entry)
{
    return entry->last_time_stamp << (64 - PAGE_THRASHING_LAST_TIME_STAMP_BITS);
}

static void page_thrashing_set_time_stamp(page_thrashing_info_t *entry, NvU64 time_stamp)
{
    entry->last_time_stamp = time_stamp >> (64 - PAGE_THRASHING_LAST_TIME_STAMP_BITS);
}

static NvU64 page_thrashing_get_throttling_end_time_stamp(page_thrashing_info_t *entry)
{
    return entry->throttling_end_time_stamp << (64 - PAGE_THRASHING_THROTTLING_END_TIME_STAMP_BITS);
}

static void page_thrashing_set_throttling_end_time_stamp(page_thrashing_info_t *entry, NvU64 time_stamp)
{
    entry->throttling_end_time_stamp = time_stamp >> (64 - PAGE_THRASHING_THROTTLING_END_TIME_STAMP_BITS);
}

// Performance heuristics module for thrashing
static uvm_perf_module_t g_module_thrashing;

// Callback declaration for the performance heuristics events
static void thrashing_event_cb(uvm_perf_event_t event_id, uvm_perf_event_data_t *event_data);
static void thrashing_block_destroy_cb(uvm_perf_event_t event_id, uvm_perf_event_data_t *event_data);

static uvm_perf_module_event_callback_desc_t g_callbacks_thrashing[] = {
    { UVM_PERF_EVENT_BLOCK_DESTROY, thrashing_block_destroy_cb },
    { UVM_PERF_EVENT_MODULE_UNLOAD, thrashing_block_destroy_cb },
    { UVM_PERF_EVENT_BLOCK_SHRINK , thrashing_block_destroy_cb },
    { UVM_PERF_EVENT_MIGRATION,     thrashing_event_cb         },
    { UVM_PERF_EVENT_REVOCATION,    thrashing_event_cb         }
};

// Get the thrashing detection struct for the given VA space if it exists
//
// VA space lock needs to be held
static va_space_thrashing_info_t *va_space_thrashing_info_get_or_null(uvm_va_space_t *va_space)
{
    uvm_assert_rwsem_locked(&va_space->lock);

    return uvm_perf_module_type_data(va_space->perf_modules_data, UVM_PERF_MODULE_TYPE_THRASHING);
}

// Get the thrashing detection struct for the given VA space. It asserts that
// the information has been previously created.
//
// VA space lock needs to be held
static va_space_thrashing_info_t *va_space_thrashing_info_get(uvm_va_space_t *va_space)
{
    va_space_thrashing_info_t *va_space_thrashing = va_space_thrashing_info_get_or_null(va_space);
    UVM_ASSERT(va_space_thrashing);

    return va_space_thrashing;
}

// Create the thrashing detection struct for the given VA space
//
// VA space lock needs to be held in write mode
static va_space_thrashing_info_t *va_space_thrashing_info_create(uvm_va_space_t *va_space)
{
    va_space_thrashing_info_t *va_space_thrashing;
    uvm_assert_rwsem_locked_write(&va_space->lock);

    UVM_ASSERT(va_space_thrashing_info_get_or_null(va_space) == NULL);

    va_space_thrashing = uvm_kvmalloc_zero(sizeof(*va_space_thrashing));
    if (va_space_thrashing) {
        uvm_perf_module_type_set_data(va_space->perf_modules_data, va_space_thrashing, UVM_PERF_MODULE_TYPE_THRASHING);

        // Snap the thrashing parameters so that they can be tuned per VA space
        va_space_thrashing->params.enable         = g_uvm_perf_thrashing_enable;
        va_space_thrashing->params.threshold      = g_uvm_perf_thrashing_threshold;
        va_space_thrashing->params.pin_threshold  = g_uvm_perf_thrashing_pin_threshold;
        va_space_thrashing->params.lapse_ns       = g_uvm_perf_thrashing_lapse_ns;
        va_space_thrashing->params.nap_ns         = g_uvm_perf_thrashing_nap_ns;
        va_space_thrashing->params.epoch_ns       = g_uvm_perf_thrashing_epoch_ns;
        va_space_thrashing->params.max_resets     = g_uvm_perf_thrashing_max_resets;
        va_space_thrashing->params.pin_ns         = g_uvm_perf_thrashing_pin_ns;

        va_space_thrashing->va_space = va_space;
    }

    return va_space_thrashing;
}

// Destroy the thrashing detection struct for the given VA space
//
// VA space lock needs to be in write mode
static void va_space_thrashing_info_destroy(uvm_va_space_t *va_space)
{
    va_space_thrashing_info_t *va_space_thrashing = va_space_thrashing_info_get_or_null(va_space);
    uvm_assert_rwsem_locked_write(&va_space->lock);

    if (va_space_thrashing) {
        uvm_perf_module_type_unset_data(va_space->perf_modules_data, UVM_PERF_MODULE_TYPE_THRASHING);
        uvm_kvfree(va_space_thrashing);
    }
}

// Get the thrashing detection struct for the given block
static block_thrashing_info_t *thrashing_info_get(uvm_va_block_t *va_block)
{
    uvm_assert_mutex_locked(&va_block->lock);
    return uvm_perf_module_type_data(va_block->perf_modules_data, UVM_PERF_MODULE_TYPE_THRASHING);
}

// Get the thrashing detection struct for the given block or create it if it
// does not exist
static block_thrashing_info_t *thrashing_info_get_create(uvm_va_block_t *va_block)
{
    block_thrashing_info_t *block_thrashing = thrashing_info_get(va_block);

    BUILD_BUG_ON((1 << 8 * sizeof(block_thrashing->num_thrashing_pages)) < PAGES_PER_UVM_VA_BLOCK);
    BUILD_BUG_ON((1 << 16) < UVM_MAX_PROCESSORS);

    if (!block_thrashing) {
        block_thrashing = kmem_cache_zalloc(g_va_block_thrashing_info_cache, NV_UVM_GFP_FLAGS);
        if (!block_thrashing)
            goto done;

        block_thrashing->last_processor = UVM_MAX_PROCESSORS;
        INIT_LIST_HEAD(&block_thrashing->pinned_pages.list);

        uvm_perf_module_type_set_data(va_block->perf_modules_data, block_thrashing, UVM_PERF_MODULE_TYPE_THRASHING);
    }

done:
    return block_thrashing;
}

static void thrashing_reset_pages_in_region(uvm_va_block_t *va_block, NvU64 address, NvU64 bytes);

// Destroy the thrashing detection struct for the given block
static void thrashing_info_destroy(uvm_va_block_t *va_block)
{
    block_thrashing_info_t *block_thrashing = thrashing_info_get(va_block);

    if (block_thrashing) {
        thrashing_reset_pages_in_region(va_block, va_block->start, uvm_va_block_size(va_block));
        uvm_kvfree(block_thrashing->pages);

        uvm_perf_module_type_unset_data(va_block->perf_modules_data, UVM_PERF_MODULE_TYPE_THRASHING);
        kmem_cache_free(g_va_block_thrashing_info_cache, block_thrashing);
    }
}

void thrashing_block_destroy_cb(uvm_perf_event_t event_id, uvm_perf_event_data_t *event_data)
{
    uvm_va_block_t *va_block;

    UVM_ASSERT(g_uvm_perf_thrashing_enable);

    UVM_ASSERT(event_id == UVM_PERF_EVENT_BLOCK_DESTROY ||
               event_id == UVM_PERF_EVENT_BLOCK_SHRINK ||
               event_id == UVM_PERF_EVENT_MODULE_UNLOAD);

    if (event_id == UVM_PERF_EVENT_BLOCK_DESTROY)
        va_block = event_data->block_destroy.block;
    else if (event_id == UVM_PERF_EVENT_BLOCK_SHRINK)
        va_block = event_data->block_shrink.block;
    else
        va_block = event_data->module_unload.block;

    if (!va_block)
        return;

    thrashing_info_destroy(va_block);
}

// Sanity checks of the thrashing tracking state
static bool thrashing_state_checks(uvm_va_block_t *va_block,
                                   block_thrashing_info_t *block_thrashing,
                                   page_thrashing_info_t *page_thrashing,
                                   uvm_page_index_t page_index)
{
    uvm_va_range_t *va_range = va_block->va_range;
    uvm_va_space_t *va_space = va_range->va_space;
    va_space_thrashing_info_t *va_space_thrashing = va_space_thrashing_info_get(va_space);

    UVM_ASSERT(va_range->type == UVM_VA_RANGE_TYPE_MANAGED);

    if (!block_thrashing) {
        UVM_ASSERT(!page_thrashing);
        return true;
    }

    UVM_ASSERT(uvm_page_mask_subset(&block_thrashing->pinned_pages.mask, &block_thrashing->thrashing_pages));

    if (page_thrashing) {
        UVM_ASSERT(block_thrashing->pages);
        UVM_ASSERT(page_thrashing == &block_thrashing->pages[page_index]);
    }
    else {
        UVM_ASSERT(!uvm_page_mask_test(&block_thrashing->thrashing_pages, page_index));
        return true;
    }

    UVM_ASSERT(uvm_processor_mask_subset(&page_thrashing->throttled_processors,
                                         &page_thrashing->processors));

    if (uvm_page_mask_test(&block_thrashing->thrashing_pages, page_index))
        UVM_ASSERT(page_thrashing->num_thrashing_events >= va_space_thrashing->params.threshold);

    if (page_thrashing->pinned) {
        UVM_ASSERT(uvm_page_mask_test(&block_thrashing->pinned_pages.mask, page_index));
        UVM_ASSERT(page_thrashing->pinned_residency != UVM_MAX_PROCESSORS);
        UVM_ASSERT(page_thrashing->throttling_count == 0);
    }
    else {
        UVM_ASSERT(!uvm_page_mask_test(&block_thrashing->pinned_pages.mask, page_index));
        UVM_ASSERT(page_thrashing->pinned_residency == UVM_MAX_PROCESSORS);

        if (!uvm_processor_mask_empty(&page_thrashing->throttled_processors)) {
            UVM_ASSERT(page_thrashing->throttling_count > 0);
            UVM_ASSERT(uvm_page_mask_test(&block_thrashing->thrashing_pages, page_index));
        }
    }

    return true;
}

// Update throttling heuristics. Mainly check if a new throttling period has
// started and choose the next processor not to be throttled. This function
// is executed before the thrashing mitigation logic kicks in.
static void thrashing_throttle_update(va_space_thrashing_info_t *va_space_thrashing,
                                      uvm_va_block_t *va_block,
                                      page_thrashing_info_t *page_thrashing,
                                      uvm_processor_id_t processor,
                                      NvU64 time_stamp)
{
    NvU64 current_end_time_stamp = page_thrashing_get_throttling_end_time_stamp(page_thrashing);

    uvm_assert_mutex_locked(&va_block->lock);

    if (time_stamp > current_end_time_stamp) {
        NvU64 throttling_end_time_stamp = time_stamp + va_space_thrashing->params.nap_ns;
        page_thrashing_set_throttling_end_time_stamp(page_thrashing, throttling_end_time_stamp);

        // Avoid choosing the same processor in consecutive thrashing periods
        if (page_thrashing->do_not_throttle_processor == processor)
            page_thrashing->do_not_throttle_processor = UVM_MAX_PROCESSORS;
        else
            page_thrashing->do_not_throttle_processor = processor;
    }
    else if (page_thrashing->do_not_throttle_processor == UVM_MAX_PROCESSORS) {
        page_thrashing->do_not_throttle_processor = processor;
    }
}

// Throttle the execution of a processor. If this is the first processor being
// throttled for a throttling period, compute the time stamp until which the
// rest of processors will be throttled on fault.
//
// - Page may be pinned (possible in thrashing due to revocation, such as
//   in system-wide atomics)
// - Requesting processor must not be throttled at this point.
//
static void thrashing_throttle_processor(uvm_va_block_t *va_block,
                                         block_thrashing_info_t *block_thrashing,
                                         page_thrashing_info_t *page_thrashing,
                                         uvm_page_index_t page_index,
                                         uvm_processor_id_t processor)
{
    uvm_va_space_t *va_space;
    NvU64 address = uvm_va_block_cpu_page_address(va_block, page_index);

    uvm_assert_mutex_locked(&va_block->lock);
    UVM_ASSERT(va_block->va_range);
    va_space = va_block->va_range->va_space;
    UVM_ASSERT(va_space);

    UVM_ASSERT(processor != page_thrashing->do_not_throttle_processor);

    if (!uvm_processor_mask_test_and_set(&page_thrashing->throttled_processors, processor)) {
        // CPU is throttled by sleeping. This is done in uvm_vm_fault so it
        // drops the VA block and VA space locks. Throttling start/end events
        // are recorded around the sleep calls.
        if (processor != UVM_CPU_ID)
            uvm_tools_record_throttling_start(va_space, address, processor);

        if (!page_thrashing->pinned)
            UVM_PERF_SATURATING_INC(page_thrashing->throttling_count);

        UVM_PERF_SATURATING_INC(block_thrashing->throttling_count);
    }

    UVM_ASSERT(thrashing_state_checks(va_block, block_thrashing, page_thrashing, page_index));
}

// Stop throttling on the given processor. If this is the last processor being
// throttled for a throttling period, it will clear the throttling period.
//
// - Page may be pinned (possible in thrashing due to revocation, such as
//   in system-wide atomics)
// - Requesting processor must be throttled at this point.
//
static void thrashing_throttle_end_processor(uvm_va_block_t *va_block,
                                             block_thrashing_info_t *block_thrashing,
                                             page_thrashing_info_t *page_thrashing,
                                             uvm_page_index_t page_index,
                                             uvm_processor_id_t processor)
{
    uvm_va_space_t *va_space;
    NvU64 address = uvm_va_block_cpu_page_address(va_block, page_index);

    UVM_ASSERT(va_block->va_range);
    va_space = va_block->va_range->va_space;
    UVM_ASSERT(va_space);

    UVM_ASSERT(uvm_processor_mask_test(&page_thrashing->throttled_processors, processor));
    uvm_processor_mask_clear(&page_thrashing->throttled_processors, processor);
    if (uvm_processor_mask_empty(&page_thrashing->throttled_processors))
        page_thrashing_set_throttling_end_time_stamp(page_thrashing, 0);

    // See comment regarding throttling start/end events for CPU in
    // thrashing_throttle_processor
    if (processor != UVM_CPU_ID)
        uvm_tools_record_throttling_end(va_space, address, processor);

    UVM_ASSERT(thrashing_state_checks(va_block, block_thrashing, page_thrashing, page_index));
}

// Clear the throttling state for all processors. This is used while
// transitioning to pinned state and during thrashing information reset.
static void thrashing_throttling_reset_page(uvm_va_block_t *va_block,
                                            block_thrashing_info_t *block_thrashing,
                                            page_thrashing_info_t *page_thrashing,
                                            uvm_page_index_t page_index)
{
    uvm_processor_id_t processor_id;

    for_each_id_in_mask(processor_id, &page_thrashing->throttled_processors) {
        thrashing_throttle_end_processor(va_block,
                                         block_thrashing,
                                         page_thrashing,
                                         page_index,
                                         processor_id);
    }

    UVM_ASSERT(uvm_processor_mask_empty(&page_thrashing->throttled_processors));
}

// Find the pinned page descriptor for the given page index. Return NULL if the
// page is not pinned.
static pinned_page_t *find_pinned_page(block_thrashing_info_t *block_thrashing, uvm_page_index_t page_index)
{
    pinned_page_t *pinned_page;

    list_for_each_entry(pinned_page, &block_thrashing->pinned_pages.list, va_block_list_entry) {
        if (pinned_page->page_index == page_index)
            return pinned_page;
    }

    return NULL;
}

// Pin a page on the specified processor. All thrashing processors will be
// mapped remotely on this location, when possible
//
// - Requesting processor cannot be throttled
//
static NV_STATUS thrashing_pin_page(va_space_thrashing_info_t *va_space_thrashing,
                                    uvm_va_block_t *va_block,
                                    block_thrashing_info_t *block_thrashing,
                                    page_thrashing_info_t *page_thrashing,
                                    uvm_page_index_t page_index,
                                    NvU64 time_stamp,
                                    uvm_processor_id_t residency,
                                    uvm_processor_id_t requester)
{
    uvm_processor_mask_t current_residency;

    uvm_assert_mutex_locked(&va_block->lock);
    UVM_ASSERT(!uvm_processor_mask_test(&page_thrashing->throttled_processors, requester));

    uvm_va_block_page_resident_processors(va_block, page_index, &current_residency);

    // If we are pinning the page for the first time or we are pinning it on a
    // different location that the current location, reset the throttling state
    // to make sure that we flush any pending ThrottlingEnd events.
    if (!page_thrashing->pinned || !uvm_processor_mask_test(&current_residency, residency))
        thrashing_throttling_reset_page(va_block, block_thrashing, page_thrashing, page_index);

    if (!page_thrashing->pinned) {
        if (va_space_thrashing->params.pin_ns > 0) {
            pinned_page_t *pinned_page = kmem_cache_zalloc(g_pinned_page_cache, NV_UVM_GFP_FLAGS);
            if (!pinned_page)
                return NV_ERR_NO_MEMORY;

            pinned_page->va_block = va_block;
            pinned_page->page_index = page_index;
            pinned_page->deadline = time_stamp + va_space_thrashing->params.pin_ns;

            uvm_spin_lock(&va_space_thrashing->pinned_pages.lock);

            list_add_tail(&pinned_page->va_space_list_entry, &va_space_thrashing->pinned_pages.list);
            list_add_tail(&pinned_page->va_block_list_entry, &block_thrashing->pinned_pages.list);

            // We only schedule the delayed work if the list was empty before
            // adding this page. Otherwise, we just add it to the list. The
            // unpinning helper will remove from the list those pages with
            // deadline prior to its wakeup timestamp and will reschedule
            // itself if there are remaining pages in the list.
            if (list_is_singular(&va_space_thrashing->pinned_pages.list) &&
                !va_space_thrashing->pinned_pages.in_va_space_teardown) {
                int scheduled;
                scheduled = schedule_delayed_work(&va_space_thrashing->pinned_pages.dwork,
                                                  usecs_to_jiffies(va_space_thrashing->params.pin_ns / 1000));
                UVM_ASSERT(scheduled != 0);
            }

            uvm_spin_unlock(&va_space_thrashing->pinned_pages.lock);
        }

        page_thrashing->throttling_count = 0;
        page_thrashing->pinned = true;
        UVM_PERF_SATURATING_INC(block_thrashing->pinned_pages.count);
        uvm_page_mask_set(&block_thrashing->pinned_pages.mask, page_index);
    }

    page_thrashing->pinned_residency = residency;

    UVM_ASSERT(thrashing_state_checks(va_block, block_thrashing, page_thrashing, page_index));

    return NV_OK;
}

// Unpin a page. This function just clears the pinning tracking state, and does
// not remove remote mappings on the page. Callers will need to do it manually
// BEFORE calling this function, if so desired.
// - Page must be pinned
//
static void thrashing_unpin_page(va_space_thrashing_info_t *va_space_thrashing,
                                 uvm_va_block_t *va_block,
                                 block_thrashing_info_t *block_thrashing,
                                 page_thrashing_info_t *page_thrashing,
                                 uvm_page_index_t page_index)
{
    uvm_assert_mutex_locked(&va_block->lock);
    UVM_ASSERT(page_thrashing->pinned);

    if (va_space_thrashing->params.pin_ns > 0) {
        pinned_page_t *pinned_page = find_pinned_page(block_thrashing, page_index);

        UVM_ASSERT(pinned_page);
        UVM_ASSERT(pinned_page->page_index == page_index);
        UVM_ASSERT(pinned_page->va_block == va_block);

        // Remove entries from the VA-space pinned page list under the lock
        uvm_spin_lock(&va_space_thrashing->pinned_pages.lock);

        list_del(&pinned_page->va_block_list_entry);
        list_del(&pinned_page->va_space_list_entry);

        // If no remaining pinned pages, cancel all scheduled work items
        if (list_empty(&va_space_thrashing->pinned_pages.list))
            cancel_delayed_work(&va_space_thrashing->pinned_pages.dwork);

        uvm_spin_unlock(&va_space_thrashing->pinned_pages.lock);

        kmem_cache_free(g_pinned_page_cache, pinned_page);
    }

    page_thrashing->pinned_residency = UVM_MAX_PROCESSORS;
    page_thrashing->pinned = false;
    uvm_page_mask_clear(&block_thrashing->pinned_pages.mask, page_index);

    UVM_ASSERT(thrashing_state_checks(va_block, block_thrashing, page_thrashing, page_index));
}

static void thrashing_detected(uvm_va_block_t *va_block,
                               block_thrashing_info_t *block_thrashing,
                               page_thrashing_info_t *page_thrashing,
                               uvm_page_index_t page_index)
{
    uvm_va_space_t *va_space;
    NvU64 address = uvm_va_block_cpu_page_address(va_block, page_index);

    UVM_ASSERT(va_block->va_range);
    va_space = va_block->va_range->va_space;
    UVM_ASSERT(va_space);

    // Thrashing detected, record the event
    uvm_tools_record_thrashing(va_space, address, PAGE_SIZE, &page_thrashing->processors);
    if (!uvm_page_mask_test_and_set(&block_thrashing->thrashing_pages, page_index))
        ++block_thrashing->num_thrashing_pages;

    UVM_ASSERT(thrashing_state_checks(va_block, block_thrashing, page_thrashing, page_index));
}

// Clear the thrashing information for the given page. This function does not
// unmap remote mappings on the page. Callers will need to do it BEFORE calling
// this function, if so desired
static void thrashing_reset_page(va_space_thrashing_info_t *va_space_thrashing,
                                 uvm_va_block_t *va_block,
                                 block_thrashing_info_t *block_thrashing,
                                 uvm_page_index_t page_index)
{
    page_thrashing_info_t *page_thrashing = &block_thrashing->pages[page_index];
    uvm_assert_mutex_locked(&va_block->lock);

    UVM_ASSERT(block_thrashing->num_thrashing_pages > 0);
    UVM_ASSERT(uvm_page_mask_test(&block_thrashing->thrashing_pages, page_index));
    UVM_ASSERT(page_thrashing->num_thrashing_events > 0);

    thrashing_throttling_reset_page(va_block, block_thrashing, page_thrashing, page_index);
    UVM_ASSERT(uvm_processor_mask_empty(&page_thrashing->throttled_processors));

    if (page_thrashing->pinned)
        thrashing_unpin_page(va_space_thrashing, va_block, block_thrashing, page_thrashing, page_index);

    page_thrashing->last_time_stamp       = 0;
    page_thrashing->has_migration_events  = 0;
    page_thrashing->has_revocation_events = 0;
    page_thrashing->num_thrashing_events  = 0;
    uvm_processor_mask_zero(&page_thrashing->processors);

    if (uvm_page_mask_test_and_clear(&block_thrashing->thrashing_pages, page_index))
        --block_thrashing->num_thrashing_pages;

    UVM_ASSERT(thrashing_state_checks(va_block, block_thrashing, page_thrashing, page_index));
}

// Call thrashing_reset_page for all the thrashing pages in the region
// described by address and bytes
static void thrashing_reset_pages_in_region(uvm_va_block_t *va_block, NvU64 address, NvU64 bytes)
{
    uvm_page_index_t page_index;
    uvm_va_space_t *va_space = va_block->va_range->va_space;
    va_space_thrashing_info_t *va_space_thrashing = va_space_thrashing_info_get(va_space);
    block_thrashing_info_t *block_thrashing = NULL;
    uvm_va_block_region_t region = uvm_va_block_region_from_start_size(va_block, address, bytes);

    block_thrashing = thrashing_info_get(va_block);
    if (!block_thrashing || !block_thrashing->pages)
        return;

    // Update all pages in the region
    for_each_va_block_page_in_region_mask(page_index, &block_thrashing->thrashing_pages, region)
        thrashing_reset_page(va_space_thrashing, va_block, block_thrashing, page_index);
}


// Unmap remote mappings from the given processors on the pinned pages
// described by region and block_thrashing->pinned pages.
static NV_STATUS unmap_remote_pinned_pages_from_processors(uvm_va_block_t *va_block,
                                                           uvm_va_block_context_t *va_block_context,
                                                           block_thrashing_info_t *block_thrashing,
                                                           uvm_va_block_region_t region,
                                                           const uvm_processor_mask_t *unmap_processors)
{
    NV_STATUS status = NV_OK;
    NV_STATUS tracker_status;
    uvm_tracker_t local_tracker = UVM_TRACKER_INIT();
    uvm_processor_id_t processor_id;
    uvm_va_range_t *va_range = va_block->va_range;

    uvm_assert_mutex_locked(&va_block->lock);

    for_each_id_in_mask(processor_id, unmap_processors) {
        UVM_ASSERT(processor_id == va_range->preferred_location ||
                   !uvm_processor_mask_test(&va_range->accessed_by, processor_id));

        if (uvm_processor_mask_test(&va_block->resident, processor_id)) {
            const uvm_page_mask_t *resident_mask = uvm_va_block_resident_mask_get(va_block, processor_id);

            if (!uvm_page_mask_andnot(&va_block_context->caller_page_mask,
                                      &block_thrashing->pinned_pages.mask,
                                      resident_mask))
                continue;
        }
        else {
            uvm_page_mask_copy(&va_block_context->caller_page_mask,
                               &block_thrashing->pinned_pages.mask);
        }

        status = uvm_va_block_unmap(va_block,
                                    va_block_context,
                                    processor_id,
                                    region,
                                    &va_block_context->caller_page_mask,
                                    &local_tracker);
        if (status != NV_OK)
            break;
    }

    tracker_status = uvm_tracker_add_tracker_safe(&va_block->tracker, &local_tracker);
    if (status == NV_OK)
        status = tracker_status;

    uvm_tracker_deinit(&local_tracker);

    return status;
}

// Unmap remote mappings from all processors on the pinned pages
// described by region and block_thrashing->pinned pages.
static NV_STATUS unmap_remote_pinned_pages_from_all_processors(uvm_va_block_t *va_block,
                                                               uvm_va_block_context_t *va_block_context,
                                                               uvm_va_block_region_t region)
{
    block_thrashing_info_t *block_thrashing;
    uvm_va_range_t *va_range = va_block->va_range;
    uvm_processor_mask_t unmap_processors;

    uvm_assert_mutex_locked(&va_block->lock);

    block_thrashing = thrashing_info_get(va_block);
    if (!block_thrashing || !block_thrashing->pages)
        return NV_OK;

    if (uvm_page_mask_empty(&block_thrashing->pinned_pages.mask))
        return NV_OK;

    // Unmap all mapped processors (that are not SetAccessedBy) with
    // no copy of the page
    uvm_processor_mask_andnot(&unmap_processors, &va_block->mapped, &va_range->accessed_by);

    return unmap_remote_pinned_pages_from_processors(va_block,
                                                     va_block_context,
                                                     block_thrashing,
                                                     region,
                                                     &unmap_processors);
}

// Unmap remote mappings from the given processor on the pinned pages described
// by region and block_thrashing->pinned pages.
static NV_STATUS unmap_remote_pinned_pages_from_processor(uvm_va_block_t *va_block,
                                                          uvm_processor_id_t processor_id,
                                                          uvm_va_block_region_t region)
{
    block_thrashing_info_t *block_thrashing;
    uvm_va_range_t *va_range = va_block->va_range;
    uvm_va_space_t *va_space = va_range->va_space;
    uvm_processor_mask_t unmap_processors;

    uvm_assert_mutex_locked(&va_block->lock);
    uvm_assert_rwsem_locked_write(&va_space->lock);

    block_thrashing = thrashing_info_get(va_block);
    UVM_ASSERT(block_thrashing && block_thrashing->pages);
    UVM_ASSERT(block_thrashing->pinned_pages.count > 0);

    if (!uvm_processor_mask_test(&va_block->mapped, processor_id))
        return NV_OK;

    uvm_processor_mask_zero(&unmap_processors);
    uvm_processor_mask_set(&unmap_processors, processor_id);

    return unmap_remote_pinned_pages_from_processors(va_block,
                                                     uvm_va_space_block_context(va_space),
                                                     block_thrashing,
                                                     region,
                                                     &unmap_processors);
}

// Check that we are not migrating pages away from its pinned location and
// that we are not prefetching thrashing pages.
static bool migrating_wrong_pages(uvm_va_block_t *va_block,
                                  NvU64 address,
                                  NvU64 bytes,
                                  uvm_processor_id_t proc_id,
                                  uvm_make_resident_cause_t cause)
{
    uvm_page_index_t page_index;
    block_thrashing_info_t *block_thrashing = NULL;
    uvm_va_block_region_t region = uvm_va_block_region_from_start_size(va_block, address, bytes);

    block_thrashing = thrashing_info_get(va_block);
    if (!block_thrashing || !block_thrashing->pages)
        return false;

    for_each_va_block_page_in_region(page_index, region) {
        page_thrashing_info_t *page_thrashing = &block_thrashing->pages[page_index];
        UVM_ASSERT_MSG(!page_thrashing->pinned || proc_id == page_thrashing->pinned_residency,
                       "Migrating to %u instead of %u\n", proc_id, page_thrashing->pinned_residency);
        if (cause == UVM_MAKE_RESIDENT_CAUSE_PREFETCH)
            UVM_ASSERT(!uvm_page_mask_test(&block_thrashing->thrashing_pages, page_index));
    }

    return false;
}

static bool is_migration_pinned_pages_update(uvm_va_block_t *va_block,
                                             const uvm_perf_event_data_t *event_data,
                                             NvU64 address,
                                             NvU64 bytes)
{
    const block_thrashing_info_t *block_thrashing = NULL;
    uvm_va_block_region_t region = uvm_va_block_region_from_start_size(va_block, address, bytes);
    bool ret;

    if (event_data->migration.cause != UVM_MAKE_RESIDENT_CAUSE_REPLAYABLE_FAULT &&
        event_data->migration.cause != UVM_MAKE_RESIDENT_CAUSE_ACCESS_COUNTER) {
        return false;
    }

    block_thrashing = thrashing_info_get(va_block);
    if (!block_thrashing || !block_thrashing->pages)
        return false;

    ret = uvm_page_mask_region_full(&block_thrashing->pinned_pages.mask, region);
    if (ret) {
        uvm_page_index_t page_index;
        for_each_va_block_page_in_region(page_index, region)
            UVM_ASSERT(block_thrashing->pages[page_index].pinned_residency == event_data->migration.dst);
    }

    return ret;
}

// Function that processes migration/revocation events and determines if there
// is the affected pages are thrashing or not.
void thrashing_event_cb(uvm_perf_event_t event_id, uvm_perf_event_data_t *event_data)
{
    va_space_thrashing_info_t *va_space_thrashing;
    block_thrashing_info_t *block_thrashing = NULL;
    uvm_va_block_t *va_block;
    uvm_va_space_t *va_space;
    NvU64 address;
    NvU64 bytes;
    uvm_processor_id_t processor_id;
    uvm_page_index_t page_index;
    NvU64 time_stamp;
    uvm_va_block_region_t region;

    UVM_ASSERT(g_uvm_perf_thrashing_enable);

    UVM_ASSERT(event_id == UVM_PERF_EVENT_MIGRATION || event_id == UVM_PERF_EVENT_REVOCATION);

    if (event_id == UVM_PERF_EVENT_MIGRATION) {
        va_block     = event_data->migration.block;
        address      = event_data->migration.address;
        bytes        = event_data->migration.bytes;
        processor_id = event_data->migration.dst;

        // Skip the thrashing detection logic on eviction as we cannot take
        // the VA space lock
        if (event_data->migration.cause == UVM_MAKE_RESIDENT_CAUSE_EVICTION)
            return;

        // Do not perform checks during the first part of staging copies
        if (event_data->migration.dst != event_data->migration.make_resident_context->dest_id)
            return;

        va_space = va_block->va_range->va_space;
        va_space_thrashing = va_space_thrashing_info_get(va_space);
        if (!va_space_thrashing->params.enable)
            return;

        // We only care about migrations due to replayable faults, access
        // counters and page prefetching. For non-replayable faults, UVM will
        // try not to migrate memory since CE is transferring data anyway.
        // However, we can still see migration events due to initial
        // population. The rest of migrations are triggered due to user
        // commands or advice (such as read duplication) which takes precedence
        // over our heuristics. Therefore, we clear our internal tracking
        // state.
        if ((event_data->migration.cause != UVM_MAKE_RESIDENT_CAUSE_REPLAYABLE_FAULT &&
             event_data->migration.cause != UVM_MAKE_RESIDENT_CAUSE_ACCESS_COUNTER &&
             event_data->migration.cause != UVM_MAKE_RESIDENT_CAUSE_PREFETCH) ||
            (event_data->migration.transfer_mode != UVM_VA_BLOCK_TRANSFER_MODE_MOVE) ||
            (va_block->va_range->read_duplication == UVM_READ_DUPLICATION_ENABLED)) {
            thrashing_reset_pages_in_region(va_block, address, bytes);
            return;
        }

        // Assert that we are not migrating pages that are pinned away from
        // their pinning residency, or prefetching pages that are thrashing
        UVM_ASSERT(!migrating_wrong_pages(va_block, address, bytes, processor_id, event_data->migration.cause));

        // If we are being migrated due to pinning just return
        if (is_migration_pinned_pages_update(va_block, event_data, address, bytes))
            return;
    }
    else {
        va_block     = event_data->revocation.block;
        address      = event_data->revocation.address;
        bytes        = event_data->revocation.bytes;
        processor_id = event_data->revocation.proc_id;

        va_space = va_block->va_range->va_space;
        va_space_thrashing = va_space_thrashing_info_get(va_space);
        if (!va_space_thrashing->params.enable)
            return;
    }

    UVM_ASSERT(va_block->va_range);
    va_space = va_block->va_range->va_space;
    UVM_ASSERT(va_space);

    block_thrashing = thrashing_info_get_create(va_block);
    if (!block_thrashing)
        return;

    time_stamp = NV_GETTIME();

    if (!block_thrashing->pages) {
        // Don't create the per-page tracking structure unless there is some potential thrashing within the block
        NvU16 num_block_pages;

        if (block_thrashing->last_time_stamp == 0 ||
            block_thrashing->last_processor == processor_id ||
            time_stamp - block_thrashing->last_time_stamp > va_space_thrashing->params.lapse_ns) {
            goto done;
        }

        num_block_pages = uvm_va_block_size(va_block) / PAGE_SIZE;

        block_thrashing->pages = uvm_kvmalloc_zero(sizeof(*block_thrashing->pages) * num_block_pages);
        if (!block_thrashing->pages)
            goto done;

        for (page_index = 0; page_index < num_block_pages; ++page_index) {
            block_thrashing->pages[page_index].pinned_residency = UVM_MAX_PROCESSORS;
            block_thrashing->pages[page_index].do_not_throttle_processor = UVM_MAX_PROCESSORS;
        }
    }

    region = uvm_va_block_region_from_start_size(va_block, address, bytes);

    // Update all pages in the region
    for_each_va_block_page_in_region(page_index, region) {
        page_thrashing_info_t *page_thrashing = &block_thrashing->pages[page_index];
        NvU64 last_time_stamp = page_thrashing_get_time_stamp(page_thrashing);

        // It is not possible that a pinned page is migrated here, since the
        // fault that triggered the migration should have unpinned it in its
        // call to uvm_perf_thrashing_get_hint. Moreover page prefetching never
        // includes pages that are thrashing (including pinning)
        if (event_id == UVM_PERF_EVENT_MIGRATION)
            UVM_ASSERT(page_thrashing->pinned == 0);

        uvm_processor_mask_set(&page_thrashing->processors, processor_id);
        page_thrashing_set_time_stamp(page_thrashing, time_stamp);

        if (last_time_stamp == 0)
            continue;

        if (time_stamp - last_time_stamp <= va_space_thrashing->params.lapse_ns) {
            UVM_PERF_SATURATING_INC(page_thrashing->num_thrashing_events);
            if (page_thrashing->num_thrashing_events == va_space_thrashing->params.threshold)
                thrashing_detected(va_block, block_thrashing, page_thrashing, page_index);

            if (page_thrashing->num_thrashing_events >= va_space_thrashing->params.threshold)
                block_thrashing->last_thrashing_time_stamp = time_stamp;

            if (event_id == UVM_PERF_EVENT_MIGRATION)
                page_thrashing->has_migration_events = true;
            else
                page_thrashing->has_revocation_events = true;
        }
        else if (page_thrashing->num_thrashing_events >= va_space_thrashing->params.threshold &&
                 !page_thrashing->pinned) {
            thrashing_reset_page(va_space_thrashing, va_block, block_thrashing, page_index);
        }
    }

done:
    block_thrashing->last_time_stamp = time_stamp;
    block_thrashing->last_processor  = processor_id;
}

static uvm_perf_thrashing_hint_t get_hint_for_migration_thrashing(va_space_thrashing_info_t *va_space_thrashing,
                                                                  uvm_va_block_t *va_block,
                                                                  uvm_page_index_t page_index,
                                                                  page_thrashing_info_t *page_thrashing,
                                                                  uvm_processor_id_t requester)
{
    uvm_perf_thrashing_hint_t hint;
    uvm_processor_id_t closest_resident_id;
    uvm_va_range_t *va_range = va_block->va_range;
    uvm_va_space_t *va_space = va_range->va_space;

    hint.type = UVM_PERF_THRASHING_HINT_TYPE_NONE;

    closest_resident_id = uvm_va_block_page_get_closest_resident_in_mask(va_block,
                                                                         page_index,
                                                                         requester,
                                                                         &page_thrashing->processors);

    // 1) If preferred_location is set, try to map to it (throttle if that's not possible)
    // 2) If NVLINK connection with support for native atomics, map it
    // 3) Else first throttle, then map (if processors do not have access,
    //    migrate, if necessary, and map to sysmem).
    if (va_range->preferred_location != UVM_MAX_PROCESSORS) {
        if (uvm_processor_mask_test(&va_space->accessible_from[va_range->preferred_location], requester)) {
            hint.type = UVM_PERF_THRASHING_HINT_TYPE_PIN;
            hint.pin.residency = va_range->preferred_location;
        }
        else if (page_thrashing->pinned && requester == page_thrashing->do_not_throttle_processor) {
            hint.type = UVM_PERF_THRASHING_HINT_TYPE_PIN;

            if (closest_resident_id != UVM_MAX_PROCESSORS &&
                uvm_processor_mask_test(&va_space->accessible_from[closest_resident_id], requester))
                hint.pin.residency = closest_resident_id;
            else
                hint.pin.residency = requester;
        }
        else if (requester != page_thrashing->do_not_throttle_processor) {
            hint.type = UVM_PERF_THRASHING_HINT_TYPE_THROTTLE;
        }

        return hint;
    }

    if (closest_resident_id != UVM_MAX_PROCESSORS) {
        uvm_processor_mask_t fast_to_residency;

        // Combine NVLINK and native atomics mask since we could have PCIe
        // atomics in the future
        uvm_processor_mask_and(&fast_to_residency,
                               &va_space->has_nvlink[closest_resident_id],
                               &va_space->has_native_atomics[closest_resident_id]);
        uvm_processor_mask_set(&fast_to_residency, closest_resident_id);

        if (uvm_processor_mask_subset(&page_thrashing->processors, &fast_to_residency)) {
            if (closest_resident_id == UVM_CPU_ID) {
                // On P9 systems, we prefer the CPU to map vidmem (since it can
                // cache it), so don't map the GPU to sysmem.
                if (requester != UVM_CPU_ID) {
                    hint.type = UVM_PERF_THRASHING_HINT_TYPE_PIN;
                    hint.pin.residency = requester;
                }
            }
            else {
                hint.type = UVM_PERF_THRASHING_HINT_TYPE_PIN;
                hint.pin.residency = closest_resident_id;
            }

            return hint;
        }
    }

    if (page_thrashing->pinned ||
        page_thrashing->throttling_count >= va_space_thrashing->params.pin_threshold) {
        hint.type = UVM_PERF_THRASHING_HINT_TYPE_PIN;

        if (page_thrashing->pinned &&
            uvm_processor_mask_test(&va_space->accessible_from[page_thrashing->pinned_residency], requester)) {
            hint.pin.residency = page_thrashing->pinned_residency;
        }
        else if (closest_resident_id != UVM_MAX_PROCESSORS &&
                 uvm_processor_mask_test(&va_space->accessible_from[closest_resident_id], requester)) {
            hint.pin.residency = closest_resident_id;
        }
        else {
            hint.pin.residency = UVM_CPU_ID;
        }
    }
    else if (requester != page_thrashing->do_not_throttle_processor) {
        hint.type = UVM_PERF_THRASHING_HINT_TYPE_THROTTLE;
    }

    return hint;
}

// Function called on fault that tells the fault handler if any operation
// should be performed to minimize thrashing. The logic is as follows:
//
// - Phase0: Block thrashing. If a number of consecutive thrashing events have
//   been detected on the VA block, per-page thrashing tracking information is
//   created.
// - Phase1: Throttling. When several processors fight over a page, we start a
//   "throttling period". During that period, only one processor will be able
//   to service faults on the page, and the rest will be throttled. All CPU
//   faults are considered to belong to the same device, even if they come from
//   different CPU threads.
// - Phase2: Pinning. After a number of consecutive throttling periods, the page
//   is pinned on a specific processor which all of the thrashing processors can
//   access.
// - Phase3: Revocation throttling. Even if the page is pinned, it can be still
//   thrashing due to revocation events (mainly due to system-wide atomics). In
//   that case we keep the page pinned while applying the same algorithm as in
//   Phase1.
uvm_perf_thrashing_hint_t uvm_perf_thrashing_get_hint(uvm_va_block_t *va_block,
                                                      NvU64 address,
                                                      uvm_processor_id_t requester)
{
    uvm_va_space_t *va_space = va_block->va_range->va_space;
    va_space_thrashing_info_t *va_space_thrashing = va_space_thrashing_info_get(va_space);
    block_thrashing_info_t *block_thrashing = NULL;
    page_thrashing_info_t *page_thrashing = NULL;
    uvm_perf_thrashing_hint_t hint;
    uvm_page_index_t page_index = uvm_va_block_cpu_page_index(va_block, address);
    NvU64 time_stamp;
    NvU64 last_time_stamp;

    hint.type = UVM_PERF_THRASHING_HINT_TYPE_NONE;

    if (!va_space_thrashing->params.enable)
        return hint;

    // If we don't have enough memory to store thrashing information, we assume
    // no thrashing
    block_thrashing = thrashing_info_get(va_block);
    if (!block_thrashing)
        return hint;

    // If the per-page tracking structure has not been created yet, we assume
    // no thrashing
    if (!block_thrashing->pages)
        return hint;

    time_stamp = NV_GETTIME();

    if (block_thrashing->last_thrashing_time_stamp != 0 &&
        (time_stamp - block_thrashing->last_thrashing_time_stamp > va_space_thrashing->params.epoch_ns) &&
        block_thrashing->pinned_pages.count == 0 &&
        block_thrashing->thrashing_reset_count < va_space_thrashing->params.max_resets) {
        uvm_page_index_t reset_page_index;

        ++block_thrashing->thrashing_reset_count;

        // Clear the state of throttled processors to make sure that we flush
        // any pending ThrottlingEnd events
        for_each_va_block_page_in_mask(reset_page_index, &block_thrashing->thrashing_pages, va_block) {
            thrashing_throttling_reset_page(va_block,
                                            block_thrashing,
                                            &block_thrashing->pages[reset_page_index],
                                            reset_page_index);
        }

        // Reset per-page tracking structure
        // TODO: Bug 1769904 [uvm8] Speculatively unpin pages that were pinned on a specific memory due to thrashing
        UVM_ASSERT(uvm_page_mask_empty(&block_thrashing->pinned_pages.mask));
        uvm_kvfree(block_thrashing->pages);
        block_thrashing->pages                     = NULL;
        block_thrashing->num_thrashing_pages       = 0;
        block_thrashing->last_processor            = UVM_MAX_PROCESSORS;
        block_thrashing->last_time_stamp           = 0;
        block_thrashing->last_thrashing_time_stamp = 0;
        uvm_page_mask_zero(&block_thrashing->thrashing_pages);
        goto done;
    }

    page_thrashing = &block_thrashing->pages[page_index];

    // Not enough thrashing events yet
    if (page_thrashing->num_thrashing_events < va_space_thrashing->params.threshold)
        goto done;

    // If the requesting processor is throttled, check the throttling end time
    // stamp
    if (uvm_processor_mask_test(&page_thrashing->throttled_processors, requester)) {
        NvU64 throttling_end_time_stamp = page_thrashing_get_throttling_end_time_stamp(page_thrashing);
        if (time_stamp < throttling_end_time_stamp && requester != page_thrashing->do_not_throttle_processor) {
            hint.type = UVM_PERF_THRASHING_HINT_TYPE_THROTTLE;
            goto done;
        }

        thrashing_throttle_end_processor(va_block, block_thrashing, page_thrashing, page_index, requester);
    }

    UVM_ASSERT(!uvm_processor_mask_test(&page_thrashing->throttled_processors, requester));

    last_time_stamp = page_thrashing_get_time_stamp(page_thrashing);

    // If the lapse since the last thrashing event is longer than a thrashing
    // lapse we are no longer thrashing
    if (time_stamp - last_time_stamp > va_space_thrashing->params.lapse_ns &&
        !page_thrashing->pinned) {
        goto done;
    }

    // Set the requesting processor in the thrashing processors mask
    uvm_processor_mask_set(&page_thrashing->processors, requester);

    UVM_ASSERT(page_thrashing->has_migration_events || page_thrashing->has_revocation_events);

    // Update throttling heuristics
    thrashing_throttle_update(va_space_thrashing, va_block, page_thrashing, requester, time_stamp);

    if (page_thrashing->pinned && page_thrashing->has_revocation_events &&
        requester != page_thrashing->do_not_throttle_processor) {

        // When we get revocation thrashing, this is due to system-wide atomics
        // downgrading the permissions of other processors. Revocations only
        // happen when several processors are mapping the same page and there
        // are no migrations. In this case, the only thing we can do is to
        // throttle the execution of the processors.
        hint.type = UVM_PERF_THRASHING_HINT_TYPE_THROTTLE;
    }
    else {
        hint = get_hint_for_migration_thrashing(va_space_thrashing,
                                                va_block,
                                                page_index,
                                                page_thrashing,
                                                requester);
    }

done:
    if (hint.type == UVM_PERF_THRASHING_HINT_TYPE_PIN) {
        NV_STATUS status = thrashing_pin_page(va_space_thrashing,
                                              va_block,
                                              block_thrashing,
                                              page_thrashing,
                                              page_index,
                                              time_stamp,
                                              hint.pin.residency,
                                              requester);

        // If there was some problem pinning the page (i.e. OOM), demote to
        // throttling)
        if (status != NV_OK)
            hint.type = UVM_PERF_THRASHING_HINT_TYPE_THROTTLE;
        else
            uvm_processor_mask_copy(&hint.pin.processors, &page_thrashing->processors);
    }

    if (hint.type == UVM_PERF_THRASHING_HINT_TYPE_THROTTLE) {
        thrashing_throttle_processor(va_block,
                                     block_thrashing,
                                     page_thrashing,
                                     page_index,
                                     requester);

        hint.throttle.end_time_stamp = page_thrashing_get_throttling_end_time_stamp(page_thrashing);
    }
    else if (hint.type == UVM_PERF_THRASHING_HINT_TYPE_NONE && page_thrashing) {
        UVM_ASSERT(!uvm_processor_mask_test(&page_thrashing->throttled_processors, requester));
        UVM_ASSERT(!page_thrashing->pinned);
        UVM_ASSERT(page_thrashing->pinned_residency == UVM_MAX_PROCESSORS);
    }

    return hint;
}

uvm_processor_mask_t *uvm_perf_thrashing_get_thrashing_processors(uvm_va_block_t *va_block, NvU64 address)
{
    uvm_va_space_t *va_space = va_block->va_range->va_space;
    va_space_thrashing_info_t *va_space_thrashing = va_space_thrashing_info_get(va_space);
    block_thrashing_info_t *block_thrashing = NULL;
    page_thrashing_info_t *page_thrashing = NULL;
    uvm_page_index_t page_index = uvm_va_block_cpu_page_index(va_block, address);

    UVM_ASSERT(g_uvm_perf_thrashing_enable);
    UVM_ASSERT(va_space_thrashing->params.enable);

    block_thrashing = thrashing_info_get(va_block);
    UVM_ASSERT(block_thrashing);

    UVM_ASSERT(block_thrashing->pages);

    page_thrashing = &block_thrashing->pages[page_index];

    return &page_thrashing->processors;
}

const uvm_page_mask_t *uvm_perf_thrashing_get_thrashing_pages(uvm_va_block_t *va_block)
{
    uvm_va_space_t *va_space = va_block->va_range->va_space;
    va_space_thrashing_info_t *va_space_thrashing = va_space_thrashing_info_get(va_space);
    block_thrashing_info_t *block_thrashing = NULL;

    if (!va_space_thrashing->params.enable)
        return NULL;

    block_thrashing = thrashing_info_get(va_block);
    if (!block_thrashing)
        return NULL;

    if (block_thrashing->num_thrashing_pages == 0)
        return NULL;

    return &block_thrashing->thrashing_pages;
}

bool uvm_perf_thrashing_is_block_thrashing(uvm_va_block_t *va_block)
{
    uvm_va_space_t *va_space = va_block->va_range->va_space;
    va_space_thrashing_info_t *va_space_thrashing = va_space_thrashing_info_get(va_space);
    block_thrashing_info_t *block_thrashing = NULL;

    if (!va_space_thrashing->params.enable)
        return false;

    block_thrashing = thrashing_info_get(va_block);
    if (!block_thrashing)
        return false;

    return block_thrashing->num_thrashing_pages > 0;
}

#define TIMER_GRANULARITY_NS 20000ULL
static void thrashing_unpin_pages(struct work_struct *work)
{
    struct delayed_work *dwork = to_delayed_work(work);
    va_space_thrashing_info_t *va_space_thrashing = container_of(dwork, va_space_thrashing_info_t, pinned_pages.dwork);
    pinned_page_t *pinned_page;
    pinned_page_t *tmp_page;
    struct list_head unpin_pages_list = LIST_HEAD_INIT(unpin_pages_list);
    NvU64 now;

    // Take the VA space lock so that VA blocks don't go away during this
    // operation.
    uvm_va_space_down_read(va_space_thrashing->va_space);

    if (va_space_thrashing->pinned_pages.in_va_space_teardown)
        goto exit_no_list_lock;

    uvm_spin_lock(&va_space_thrashing->pinned_pages.lock);

    // If there are no entries, we are done
    if (list_empty(&va_space_thrashing->pinned_pages.list))
        goto unlock;

    now = NV_GETTIME();

    // Create a list with the pages that need to be unpinned
    list_for_each_entry(pinned_page, &va_space_thrashing->pinned_pages.list, va_space_list_entry) {
        if (pinned_page->deadline > (now + TIMER_GRANULARITY_NS)) {
            // Re-schedule timer for the next page to be unpinned
            NvU64 elapsed_us = (pinned_page->deadline - now) / 1000;

            schedule_delayed_work(&va_space_thrashing->pinned_pages.dwork, usecs_to_jiffies(elapsed_us));
            break;
        }
    }

    list_cut_position(&unpin_pages_list, &va_space_thrashing->pinned_pages.list, pinned_page->va_space_list_entry.prev);

unlock:
    uvm_spin_unlock(&va_space_thrashing->pinned_pages.lock);

    // This list traversal needs to be safe becase thrashing_reset_page deletes
    // pinned_page from va_space_list_entry
    list_for_each_entry_safe(pinned_page, tmp_page, &unpin_pages_list, va_space_list_entry) {
        block_thrashing_info_t *block_thrashing;
        uvm_page_index_t page_index = pinned_page->page_index;
        uvm_va_block_t *va_block = pinned_page->va_block;

        uvm_mutex_lock(&va_block->lock);

        block_thrashing = thrashing_info_get(va_block);
        if (block_thrashing) {
            unmap_remote_pinned_pages_from_all_processors(va_block,
                                                          &va_space_thrashing->pinned_pages.va_block_context,
                                                          uvm_va_block_region_for_page(page_index));

            thrashing_reset_page(va_space_thrashing, va_block, block_thrashing, page_index);
        }

        uvm_mutex_unlock(&va_block->lock);
    }

exit_no_list_lock:
    uvm_va_space_up_read(va_space_thrashing->va_space);
}

NV_STATUS uvm_perf_thrashing_load(uvm_va_space_t *va_space)
{
    va_space_thrashing_info_t *va_space_thrashing;
    NV_STATUS status;

    status = uvm_perf_module_load(&g_module_thrashing, va_space);
    if (status != NV_OK)
        return status;

    va_space_thrashing = va_space_thrashing_info_create(va_space);
    if (!va_space_thrashing)
        return NV_ERR_NO_MEMORY;

    uvm_spin_lock_init(&va_space_thrashing->pinned_pages.lock, UVM_LOCK_ORDER_LEAF);
    INIT_LIST_HEAD(&va_space_thrashing->pinned_pages.list);
    INIT_DELAYED_WORK(&va_space_thrashing->pinned_pages.dwork, thrashing_unpin_pages);

    return NV_OK;
}

void uvm_perf_thrashing_stop(uvm_va_space_t *va_space)
{
    va_space_thrashing_info_t *va_space_thrashing;

    uvm_va_space_down_write(va_space);
    va_space_thrashing = va_space_thrashing_info_get_or_null(va_space);

    // Prevent further unpinning operations from being scheduled
    if (va_space_thrashing)
        va_space_thrashing->pinned_pages.in_va_space_teardown = true;

    uvm_va_space_up_write(va_space);

    // Cancel any pending work. We can safely access va_space_thrashing
    // because this function is called once from the VA space teardown path,
    // and the only function that frees it is uvm_perf_thrashing_unload,
    // which is called later in the teardown path.
    if (va_space_thrashing)
        (void)cancel_delayed_work_sync(&va_space_thrashing->pinned_pages.dwork);
}

void uvm_perf_thrashing_unload(uvm_va_space_t *va_space)
{
    va_space_thrashing_info_t *va_space_thrashing = va_space_thrashing_info_get_or_null(va_space);

    uvm_perf_module_unload(&g_module_thrashing, va_space);

    // Make sure that there are not pending work items
    if (va_space_thrashing) {
        UVM_ASSERT(va_space_thrashing->pinned_pages.in_va_space_teardown);
        UVM_ASSERT(list_empty(&va_space_thrashing->pinned_pages.list));

        va_space_thrashing_info_destroy(va_space);
    }
}

NV_STATUS uvm_perf_thrashing_init()
{
    NV_STATUS status;
    g_uvm_perf_thrashing_enable = uvm_perf_thrashing_enable != 0;

    if (!g_uvm_perf_thrashing_enable)
        return NV_OK;

    uvm_perf_module_init("perf_thrashing",
                         UVM_PERF_MODULE_TYPE_THRASHING,
                         g_callbacks_thrashing,
                         ARRAY_SIZE(g_callbacks_thrashing),
                         &g_module_thrashing);

    if (uvm_perf_thrashing_threshold != 0 && uvm_perf_thrashing_threshold <= UVM_PERF_THRASHING_THRESHOLD_MAX) {
        g_uvm_perf_thrashing_threshold = uvm_perf_thrashing_threshold;
    }
    else {
        pr_info("Invalid value %u for uvm_perf_thrashing_threshold. Using %u instead\n",
                uvm_perf_thrashing_threshold,
                UVM_PERF_THRASHING_THRESHOLD_DEFAULT);

        g_uvm_perf_thrashing_threshold = UVM_PERF_THRASHING_THRESHOLD_DEFAULT;
    }

    if (uvm_perf_thrashing_pin_threshold != 0 && uvm_perf_thrashing_pin_threshold <= UVM_PERF_THRASHING_PIN_THRESHOLD_MAX) {
        g_uvm_perf_thrashing_pin_threshold = uvm_perf_thrashing_pin_threshold;
    }
    else {
        pr_info("Invalid value %u for uvm_perf_thrashing_pin_threshold. Using %u instead\n",
                uvm_perf_thrashing_pin_threshold,
                UVM_PERF_THRASHING_PIN_THRESHOLD_DEFAULT);

        g_uvm_perf_thrashing_pin_threshold = UVM_PERF_THRASHING_PIN_THRESHOLD_DEFAULT;
    }

    if (uvm_perf_thrashing_lapse_usec != 0) {
        g_uvm_perf_thrashing_lapse_ns = ((NvU64)uvm_perf_thrashing_lapse_usec) * 1000;
    }
    else {
        pr_info("Invalid value %u for uvm_perf_thrashing_lapse_usec. Using %u instead\n",
                uvm_perf_thrashing_lapse_usec,
                UVM_PERF_THRASHING_LAPSE_USEC_DEFAULT);

        g_uvm_perf_thrashing_lapse_ns = ((NvU64)UVM_PERF_THRASHING_LAPSE_USEC_DEFAULT) * 1000;
    }

    if (uvm_perf_thrashing_nap_usec != 0 && uvm_perf_thrashing_nap_usec <= UVM_PERF_THRASHING_NAP_USEC_MAX) {
        g_uvm_perf_thrashing_nap_ns   = ((NvU64)uvm_perf_thrashing_nap_usec) * 1000;
    }
    else {
        pr_info("Invalid value %u for uvm_perf_thrashing_nap_usec. Using %u instead\n",
                uvm_perf_thrashing_nap_usec,
                UVM_PERF_THRASHING_NAP_USEC_DEFAULT);

        g_uvm_perf_thrashing_nap_ns = ((NvU64)UVM_PERF_THRASHING_NAP_USEC_DEFAULT) * 1000;
    }

    if (uvm_perf_thrashing_epoch_msec != 0 && uvm_perf_thrashing_epoch_msec * 1000 > uvm_perf_thrashing_lapse_usec) {
        g_uvm_perf_thrashing_epoch_ns = ((NvU64)uvm_perf_thrashing_epoch_msec) * 1000 * 1000;
    }
    else {
        pr_info("Invalid value %u for uvm_perf_thrashing_epoch_msec. Using %u instead\n",
                uvm_perf_thrashing_epoch_msec,
                UVM_PERF_THRASHING_EPOCH_MSEC_DEFAULT);

        g_uvm_perf_thrashing_epoch_ns = ((NvU64)UVM_PERF_THRASHING_EPOCH_MSEC_DEFAULT) * 1000 * 1000;
    }

    if (uvm_perf_thrashing_pin_msec != 0 &&
        uvm_perf_thrashing_pin_msec * 1000 > uvm_perf_thrashing_lapse_usec) {
        g_uvm_perf_thrashing_pin_ns = ((NvU64)uvm_perf_thrashing_pin_msec) * 1000 * 1000;
    }
    else {
        pr_info("Invalid value %u for uvm_perf_thrashing_pin_msec. Using %u instead\n",
                uvm_perf_thrashing_pin_msec,
                UVM_PERF_THRASHING_PIN_MSEC_DEFAULT);

        g_uvm_perf_thrashing_pin_ns = ((NvU64)UVM_PERF_THRASHING_PIN_MSEC_DEFAULT) * 1000 * 1000;
    }

    g_uvm_perf_thrashing_max_resets = uvm_perf_thrashing_max_resets;

    g_va_block_thrashing_info_cache = NV_KMEM_CACHE_CREATE("uvm_block_thrashing_info_t", block_thrashing_info_t);
    if (!g_va_block_thrashing_info_cache) {
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    g_pinned_page_cache = NV_KMEM_CACHE_CREATE("uvm_pinned_page_t", pinned_page_t);
    if (!g_pinned_page_cache) {
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    return NV_OK;

error:
    uvm_perf_thrashing_exit();

    return status;
}

void uvm_perf_thrashing_exit()
{
    kmem_cache_destroy_safe(&g_va_block_thrashing_info_cache);
    kmem_cache_destroy_safe(&g_pinned_page_cache);
}

NV_STATUS uvm8_test_get_page_thrashing_policy(UVM_TEST_GET_PAGE_THRASHING_POLICY_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    va_space_thrashing_info_t *va_space_thrashing;

    uvm_va_space_down_read(va_space);

    va_space_thrashing = va_space_thrashing_info_get(va_space);

    if (va_space_thrashing->params.enable) {
        params->policy = UVM_TEST_PAGE_THRASHING_POLICY_ENABLE;
        params->pin_ns = va_space_thrashing->params.pin_ns;
        params->map_remote_on_native_atomics_fault = uvm_perf_map_remote_on_native_atomics_fault != 0;
    }
    else {
        params->policy = UVM_TEST_PAGE_THRASHING_POLICY_DISABLE;
    }

    uvm_va_space_up_read(va_space);

    return NV_OK;
}

NV_STATUS uvm8_test_set_page_thrashing_policy(UVM_TEST_SET_PAGE_THRASHING_POLICY_PARAMS *params, struct file *filp)
{
    NV_STATUS status = NV_OK;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    va_space_thrashing_info_t *va_space_thrashing;

    if (params->policy >= UVM_TEST_PAGE_THRASHING_POLICY_MAX)
        return NV_ERR_INVALID_ARGUMENT;

    if (!g_uvm_perf_thrashing_enable)
        return NV_ERR_INVALID_STATE;

    uvm_va_space_down_write(va_space);

    va_space_thrashing = va_space_thrashing_info_get(va_space);

    if (params->policy == UVM_TEST_PAGE_THRASHING_POLICY_ENABLE) {
        if (va_space_thrashing->params.enable)
            goto done_unlock_va_space;

        va_space_thrashing->params.pin_ns = params->pin_ns;
        va_space_thrashing->params.enable = true;
    }
    else {
        if (!va_space_thrashing->params.enable)
            goto done_unlock_va_space;

        va_space_thrashing->params.enable = false;
    }

    // When disabling thrashing detection, destroy the thrashing tracking
    // information for all VA blocks and unpin pages
    if (!va_space_thrashing->params.enable) {
        uvm_va_range_t *va_range;

        uvm_for_each_va_range(va_range, va_space) {
            uvm_va_block_t *va_block;

            if (va_range->type != UVM_VA_RANGE_TYPE_MANAGED)
                continue;

            for_each_va_block_in_va_range(va_range, va_block) {
                uvm_va_block_region_t va_block_region = uvm_va_block_region_from_block(va_block);

                uvm_mutex_lock(&va_block->lock);

                // Unmap may split PTEs and require a retry. Needs to be called
                // before the pinned pages information is destroyed.
                status = UVM_VA_BLOCK_RETRY_LOCKED(va_block,
                                                   NULL,
                                                   unmap_remote_pinned_pages_from_all_processors(va_block,
                                                                                                 uvm_va_space_block_context(va_space),
                                                                                                 va_block_region));

                thrashing_info_destroy(va_block);

                uvm_mutex_unlock(&va_block->lock);

                // Re-enable thrashing on failure to avoid getting asserts
                // about having state while thrashing is disabled
                if (status != NV_OK) {
                    va_space_thrashing->params.enable = true;
                    goto done_unlock_va_space;
                }
            }
        }
    }

done_unlock_va_space:
    uvm_va_space_up_write(va_space);

    return status;
}
