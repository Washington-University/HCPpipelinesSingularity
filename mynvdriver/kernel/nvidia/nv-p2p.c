/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2011 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#define  __NO_VERSION__
#include "nv-misc.h"

#include "os-interface.h"
#include "nv-linux.h"
#include "nv-ibmnpu.h"
#include "nv-rsync.h"

#if (NV_BUILD_MODULE_INSTANCES == 0)
#include "nv-p2p.h"
#include "rmp2pdefines.h"

// declared and created in nv.c
extern void *nvidia_p2p_page_t_cache;

static struct nvidia_status_mapping {
    NV_STATUS status;
    int error;
} nvidia_status_mappings[] = {
    { NV_ERR_GENERIC,                -EIO      },
    { NV_ERR_INSUFFICIENT_RESOURCES, -ENOMEM   },
    { NV_ERR_NO_MEMORY,              -ENOMEM   },
    { NV_ERR_INVALID_ARGUMENT,       -EINVAL   },
    { NV_ERR_INVALID_OBJECT_HANDLE,  -EINVAL   },
    { NV_ERR_INVALID_STATE,          -EIO      },
    { NV_ERR_NOT_SUPPORTED,          -ENOTSUPP },
    { NV_ERR_OBJECT_NOT_FOUND,       -EINVAL   },
    { NV_ERR_STATE_IN_USE,           -EBUSY    },
    { NV_OK,                          0        },
};

#define NVIDIA_STATUS_MAPPINGS \
    (sizeof(nvidia_status_mappings) / sizeof(struct nvidia_status_mapping))

static int nvidia_p2p_map_status(NV_STATUS status)
{
    int error = -EIO;
    uint8_t i;

    for (i = 0; i < NVIDIA_STATUS_MAPPINGS; i++)
    {
        if (nvidia_status_mappings[i].status == status)
        {
            error = nvidia_status_mappings[i].error;
            break;
        }
    }
    return error;
}

static NvU32 nvidia_p2p_page_size_mappings[NVIDIA_P2P_PAGE_SIZE_COUNT] = {
    NVRM_P2P_PAGESIZE_SMALL_4K, NVRM_P2P_PAGESIZE_BIG_64K, NVRM_P2P_PAGESIZE_BIG_128K
};

static NV_STATUS nvidia_p2p_map_page_size(NvU32 page_size, NvU32 *page_size_index)
{
    NvU32 i;

    for (i = 0; i < NVIDIA_P2P_PAGE_SIZE_COUNT; i++)
    {
        if (nvidia_p2p_page_size_mappings[i] == page_size)
        {
            *page_size_index = i;
            break;
        }
    }

    if (i == NVIDIA_P2P_PAGE_SIZE_COUNT)
        return NV_ERR_GENERIC;

    return NV_OK;
}

int nvidia_p2p_init_mapping(
    uint64_t p2p_token,
    struct nvidia_p2p_params *params,
    void (*destroy_callback)(void *data),
    void *data
)
{
    nvidia_stack_t *sp = NULL;
    NV_STATUS status;
    union nvidia_p2p_mailbox_addresses *gpu, *tpd;
    int rc;

    if ((p2p_token == 0) || (params == NULL))
        return -EINVAL;

    if ((params->version > NVIDIA_P2P_PARAMS_VERSION) ||
        (params->architecture != NVIDIA_P2P_ARCHITECTURE_FERMI))
    {
        return -ENOTSUPP;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    gpu = &params->addresses[NVIDIA_P2P_PARAMS_ADDRESS_INDEX_GPU];
    tpd = &params->addresses[NVIDIA_P2P_PARAMS_ADDRESS_INDEX_THIRD_PARTY_DEVICE];

    status = rm_p2p_init_mapping(sp, p2p_token, &gpu->fermi.wmb_addr,
            &gpu->fermi.wmb_data, &gpu->fermi.rreq_addr,
            &gpu->fermi.rcomp_addr, tpd->fermi.wmb_addr,
            tpd->fermi.wmb_data, tpd->fermi.rreq_addr, tpd->fermi.rcomp_addr,
            destroy_callback, data);

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}

EXPORT_SYMBOL(nvidia_p2p_init_mapping);

int nvidia_p2p_destroy_mapping(uint64_t p2p_token)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    int rc;

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    status = rm_p2p_destroy_mapping(sp, p2p_token);

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}

EXPORT_SYMBOL(nvidia_p2p_destroy_mapping);

int nvidia_p2p_get_pages(
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    uint64_t length,
    struct nvidia_p2p_page_table **page_table,
    void (*free_callback)(void * data),
    void *data
)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    struct nvidia_p2p_page *page;
    NvU32 entries;
    NvU32 *wreqmb_h = NULL;
    NvU32 *rreqmb_h = NULL;
    NvU64 *physical_addresses = NULL;
    NvU32 page_count;
    NvU32 i = 0;
    NvBool bGetPages = NV_FALSE;
    NvU32 page_size = NVRM_P2P_PAGESIZE_BIG_64K;
    NvU32 page_size_index;
    NvU64 temp_length;
    NvU8 *gpu_uuid = NULL;
    int rc;

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    *page_table = NULL;
    status = os_alloc_mem((void **)page_table, sizeof(**page_table));
    if (status != NV_OK)
    {
        goto failed;
    }
    memset(*page_table, 0, sizeof(**page_table));

    //asign length to temporary variable since do_div macro does in-place division
    temp_length = length;
    do_div(temp_length, page_size);
    page_count = temp_length;

    if (length & (page_size - 1))
    {
        page_count++;
    }

    status = os_alloc_mem((void **)&physical_addresses,
            (page_count * sizeof(NvU64)));
    if (status != NV_OK)
    {
        goto failed;
    }
    status = os_alloc_mem((void **)&wreqmb_h, (page_count * sizeof(NvU32)));
    if (status != NV_OK)
    {
        goto failed;
    }
    status = os_alloc_mem((void **)&rreqmb_h, (page_count * sizeof(NvU32)));
    if (status != NV_OK)
    {
        goto failed;
    }

    status = rm_p2p_get_pages(sp, p2p_token, va_space,
            virtual_address, length, physical_addresses, wreqmb_h,
            rreqmb_h, &entries, &gpu_uuid, *page_table,
            free_callback, data);
    if (status != NV_OK)
    {
        goto failed;
    }

    bGetPages = NV_TRUE;
    (*page_table)->gpu_uuid = gpu_uuid;

    status = os_alloc_mem((void *)&(*page_table)->pages,
             (entries * sizeof(page)));
    if (status != NV_OK)
    {
        goto failed;
    }
 
    (*page_table)->version = NVIDIA_P2P_PAGE_TABLE_VERSION;

    for (i = 0; i < entries; i++)
    {
        page = NV_KMEM_CACHE_ALLOC(nvidia_p2p_page_t_cache);
        if (page == NULL)
        {
            goto failed;
        }

        memset(page, 0, sizeof(*page));

        page->physical_address = physical_addresses[i];
        page->registers.fermi.wreqmb_h = wreqmb_h[i];
        page->registers.fermi.rreqmb_h = rreqmb_h[i];

        (*page_table)->pages[i] = page;
        (*page_table)->entries++;
    }

    status = nvidia_p2p_map_page_size(page_size, &page_size_index);
    if (status != NV_OK)
    {
        goto failed;
    }

    (*page_table)->page_size = page_size_index;
    
    os_free_mem(physical_addresses);
    os_free_mem(wreqmb_h);
    os_free_mem(rreqmb_h);

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);

failed:
    if (physical_addresses != NULL)
    {
        os_free_mem(physical_addresses);
    }
    if (wreqmb_h != NULL)
    {
        os_free_mem(wreqmb_h);
    }
    if (rreqmb_h != NULL)
    {
        os_free_mem(rreqmb_h);
    }

    if (bGetPages)
    {
        rm_p2p_put_pages(sp, p2p_token, va_space, virtual_address, *page_table);
    }

    if (*page_table != NULL)
    {
        nvidia_p2p_free_page_table(*page_table);
    }

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}

EXPORT_SYMBOL(nvidia_p2p_get_pages);

int nvidia_p2p_free_page_table(struct nvidia_p2p_page_table *page_table)
{
    NvU32 i;

    if (page_table == NULL)
        return -EINVAL;

    for (i = 0; i < page_table->entries; i++)
    {
        NV_KMEM_CACHE_FREE(page_table->pages[i], nvidia_p2p_page_t_cache);
    }

    if (page_table->gpu_uuid != NULL)
    {
        os_free_mem(page_table->gpu_uuid);
    }

    if (page_table->pages != NULL)
    {
        os_free_mem(page_table->pages);
    }

    os_free_mem(page_table);

    return 0;
}

EXPORT_SYMBOL(nvidia_p2p_free_page_table);

int nvidia_p2p_put_pages(
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    struct nvidia_p2p_page_table *page_table
)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    int rc;

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    status = rm_p2p_put_pages(sp, p2p_token, va_space, virtual_address, page_table);
    if (status == NV_OK)
        nvidia_p2p_free_page_table(page_table);

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}

EXPORT_SYMBOL(nvidia_p2p_put_pages);

int nvidia_p2p_dma_map_pages(
    struct pci_dev *peer,
    struct nvidia_p2p_page_table *page_table,
    struct nvidia_p2p_dma_mapping **dma_mapping
)
{
    NV_STATUS status;
    nv_state_t *peer_nv = NULL;
    nv_linux_state_t *peer_nvl = NULL;
    nvidia_stack_t *sp = NULL;
    NvU64 *dma_addresses = NULL;
    NvU32 page_count;
    NvU32 page_size;
    enum nvidia_p2p_page_size_type page_size_type;
    NvU32 i;
    void *priv;
    int rc;

    if (peer == NULL || page_table == NULL || dma_mapping == NULL ||
        page_table->gpu_uuid == NULL)
    {
        return -EINVAL;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    *dma_mapping = NULL;
    status = os_alloc_mem((void **)dma_mapping, sizeof(**dma_mapping));
    if (status != NV_OK)
    {
        goto failed;
    }
    memset(*dma_mapping, 0, sizeof(**dma_mapping));

    page_count = page_table->entries;

    status = os_alloc_mem((void **)&dma_addresses,
            (page_count * sizeof(NvU64)));
    if (status != NV_OK)
    {
        goto failed;
    }

    page_size_type = page_table->page_size;

    BUG_ON((page_size_type <= NVIDIA_P2P_PAGE_SIZE_4KB) ||
           (page_size_type >= NVIDIA_P2P_PAGE_SIZE_COUNT));

    status = os_alloc_mem((void **)&peer_nvl, sizeof(nv_linux_state_t));
    if (status != NV_OK)
    {
        goto failed;
    }

    os_mem_set(peer_nvl, 0, sizeof(nv_linux_state_t));

    peer_nvl->dev = peer;

    peer_nv = NV_STATE_PTR(peer_nvl);

    peer_nv->dma_addressable_start = 0;
    peer_nv->dma_addressable_limit = peer->dma_mask;
    peer_nv->os_state = peer_nvl;

    page_size = nvidia_p2p_page_size_mappings[page_size_type];

    for (i = 0; i < page_count; i++)
    {
        dma_addresses[i] = page_table->pages[i]->physical_address;
    }

    status = rm_p2p_dma_map_pages(sp, peer_nv,
            page_table->gpu_uuid, page_size, page_count, dma_addresses, &priv);
    if (status != NV_OK)
    {
        goto failed;
    }

    (*dma_mapping)->version = NVIDIA_P2P_DMA_MAPPING_VERSION;
    (*dma_mapping)->page_size_type = page_size_type;
    (*dma_mapping)->entries = page_count;
    (*dma_mapping)->dma_addresses = dma_addresses;
    (*dma_mapping)->private = priv;
    (*dma_mapping)->dev = peer;

failed:
    nv_kmem_cache_free_stack(sp);
    if (peer_nvl != NULL)
    {
        os_free_mem(peer_nvl);
    }

    if ((status != NV_OK ) && (dma_mapping != NULL))
    {
        if (dma_addresses != NULL)
        {
            os_free_mem(dma_addresses);
        }
        os_free_mem(dma_mapping);
    }

    return nvidia_p2p_map_status(status);
}

EXPORT_SYMBOL(nvidia_p2p_dma_map_pages);

int nvidia_p2p_dma_unmap_pages(
    struct pci_dev *peer,
    struct nvidia_p2p_page_table *page_table,
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    NV_STATUS status;
    nv_state_t *peer_nv = NULL;
    nv_linux_state_t *peer_nvl = NULL;
    nvidia_stack_t *sp = NULL;
    NvU32 page_size;
    NvU32 i;
    int rc;

    if (peer == NULL || dma_mapping == NULL)
    {
        return -EINVAL;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    BUG_ON((dma_mapping->page_size_type <= NVIDIA_P2P_PAGE_SIZE_4KB) ||
           (dma_mapping->page_size_type >= NVIDIA_P2P_PAGE_SIZE_COUNT));

    status = os_alloc_mem((void **)&peer_nvl, sizeof(nv_linux_state_t));
    if (status != NV_OK)
    {
        goto failed;
    }

    os_mem_set(peer_nvl, 0, sizeof(nv_linux_state_t));

    WARN_ON(peer != dma_mapping->dev);

    peer_nvl->dev = dma_mapping->dev;

    peer_nv = NV_STATE_PTR(peer_nvl);

    peer_nv->dma_addressable_start = 0;
    peer_nv->dma_addressable_limit = peer->dma_mask;
    peer_nv->os_state = peer_nvl;

    page_size = nvidia_p2p_page_size_mappings[dma_mapping->page_size_type];

    if (dma_mapping->private)
    {
        WARN_ON(page_size != PAGE_SIZE);

        status = nv_dma_unmap_alloc(peer_nv,
                                    dma_mapping->entries,
                                    dma_mapping->dma_addresses,
                                    &dma_mapping->private);
    }
    else
    {
        for (i = 0; i < dma_mapping->entries; i++)
        {
            nv_dma_unmap_peer(peer_nv, page_size / PAGE_SIZE,
                              dma_mapping->dma_addresses[i]);
        }
    }

failed:
    nv_kmem_cache_free_stack(sp);
    if (peer_nvl != NULL)
    {
        os_free_mem(peer_nvl);
    }

    os_free_mem(dma_mapping->dma_addresses);

    os_free_mem(dma_mapping);

    return nvidia_p2p_map_status(status);
}

EXPORT_SYMBOL(nvidia_p2p_dma_unmap_pages);

int nvidia_p2p_free_dma_mapping(
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    int rc;

    if (dma_mapping == NULL)
    {
        return -EINVAL;
    }

    rc = nvidia_p2p_dma_unmap_pages(dma_mapping->dev, NULL, dma_mapping);

    return rc;
}

EXPORT_SYMBOL(nvidia_p2p_free_dma_mapping);

int nvidia_p2p_register_rsync_driver(
    nvidia_p2p_rsync_driver_t *driver,
    void *data
)
{
    if (driver == NULL)
    {
        return -EINVAL;
    }

    if (!NVIDIA_P2P_RSYNC_DRIVER_VERSION_COMPATIBLE(driver))
    {
        return -EINVAL;
    }

    if (driver->get_relaxed_ordering_mode == NULL ||
        driver->put_relaxed_ordering_mode == NULL ||
        driver->wait_for_rsync == NULL)
    {
        return -EINVAL;
    }

    return nv_register_rsync_driver(driver->get_relaxed_ordering_mode,
                                    driver->put_relaxed_ordering_mode,
                                    driver->wait_for_rsync, data);
}

EXPORT_SYMBOL(nvidia_p2p_register_rsync_driver);

void nvidia_p2p_unregister_rsync_driver(
    nvidia_p2p_rsync_driver_t *driver,
    void *data
)
{
    if (driver == NULL)
    {
        WARN_ON(1);
        return;
    }

    if (!NVIDIA_P2P_RSYNC_DRIVER_VERSION_COMPATIBLE(driver))
    {
        WARN_ON(1);
        return;
    }

    if (driver->get_relaxed_ordering_mode == NULL ||
        driver->put_relaxed_ordering_mode == NULL ||
        driver->wait_for_rsync == NULL)
    {
        WARN_ON(1);
        return;
    }

    nv_unregister_rsync_driver(driver->get_relaxed_ordering_mode,
                               driver->put_relaxed_ordering_mode,
                               driver->wait_for_rsync, data);
}

EXPORT_SYMBOL(nvidia_p2p_unregister_rsync_driver);

int nvidia_p2p_get_rsync_registers(
    nvidia_p2p_rsync_reg_info_t **reg_info
)
{
    nv_linux_state_t *nvl;
    nv_state_t *nv;
    NV_STATUS status;
    void *ptr = NULL;
    NvU64 addr;
    NvU64 size;
    struct pci_dev *ibmnpu = NULL;
    NvU32 index = 0;
    NvU32 count = 0;
    nvidia_p2p_rsync_reg_info_t *info = NULL;
    nvidia_p2p_rsync_reg_t *regs = NULL;

    if (reg_info == NULL)
    {
        return -EINVAL;
    }

    status = os_alloc_mem((void**)&info, sizeof(*info));
    if (status != NV_OK)
    {
        return -ENOMEM;
    }

    memset(info, 0, sizeof(*info));

    info->version = NVIDIA_P2P_RSYNC_REG_INFO_VERSION;

    LOCK_NV_LINUX_DEVICES();

    for (nvl = nv_linux_devices; nvl; nvl = nvl->next)
    {
        count++;
    }

    status = os_alloc_mem((void**)&regs, (count * sizeof(*regs)));
    if (status != NV_OK)
    {
        nvidia_p2p_put_rsync_registers(info);
        UNLOCK_NV_LINUX_DEVICES();
        return -ENOMEM;
    }

    for (nvl = nv_linux_devices; nvl; nvl = nvl->next)
    {
        nv = NV_STATE_PTR(nvl);

        addr = 0;
        size = 0;

        status = nv_get_ibmnpu_genreg_info(nv, &addr, &size, (void**)&ibmnpu);
        if (status != NV_OK)
        {
            continue;
        }

        ptr = nv_ioremap_nocache(addr, size);
        if (ptr == NULL)
        {
            continue;
        }

        regs[index].ptr = ptr;
        regs[index].size = size;
        regs[index].gpu = nvl->dev;
        regs[index].ibmnpu = ibmnpu;
        regs[index].cluster_id = 0;
        regs[index].socket_id = nv_get_ibmnpu_chip_id(nv);

        index++;
    }

    UNLOCK_NV_LINUX_DEVICES();

    info->regs = regs;
    info->entries = index;

    if (info->entries == 0)
    {
        nvidia_p2p_put_rsync_registers(info);
        return -ENODEV;
    }

    *reg_info = info;

    return 0;
}

EXPORT_SYMBOL(nvidia_p2p_get_rsync_registers);

void nvidia_p2p_put_rsync_registers(
    nvidia_p2p_rsync_reg_info_t *reg_info
)
{
    NvU32 i;
    nvidia_p2p_rsync_reg_t *regs = NULL;

    if (reg_info == NULL)
    {
        return;
    }

    if (reg_info->regs)
    {
        for (i = 0; i < reg_info->entries; i++)
        {
            regs = &reg_info->regs[i];

            if (regs->ptr)
            {
                nv_iounmap(regs->ptr, regs->size);
            }
        }

        os_free_mem(reg_info->regs);
    }

    os_free_mem(reg_info);
}

EXPORT_SYMBOL(nvidia_p2p_put_rsync_registers);

#endif
