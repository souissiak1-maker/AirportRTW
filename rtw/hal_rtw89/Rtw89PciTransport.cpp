/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include "Rtw89PciTransport.hpp"

#include <IOKit/IOLib.h>
#include <kern/sched_prim.h>

extern "C" {
#include "compat/rtw88_compat.h"
#include "compat/linux/dma-mapping.h"
#include "compat/linux/pci.h"
void rtw88_trigger_interrupt(void);
}

OSDefineMetaClassAndStructors(Rtw89PciTransport, OSObject)

Rtw89PciTransport *Rtw89PciTransport::active = nullptr;

namespace {
struct pci_ops_rtw88 pciOperations = {
    Rtw89PciTransport::readConfigByte,
    Rtw89PciTransport::readConfigWord,
    Rtw89PciTransport::readConfigDword,
    Rtw89PciTransport::writeConfigByte,
    Rtw89PciTransport::writeConfigWord,
    Rtw89PciTransport::writeConfigDword,
    Rtw89PciTransport::mapBAR,
    Rtw89PciTransport::unmapBAR,
    Rtw89PciTransport::enableMSI,
    Rtw89PciTransport::disableMSI,
    Rtw89PciTransport::findCapability,
};

struct rtw88_dma_alloc_ops dmaOperations = {
    Rtw89PciTransport::allocateCoherent,
    Rtw89PciTransport::freeCoherent,
    Rtw89PciTransport::mapSingle,
    Rtw89PciTransport::unmapSingle,
    Rtw89PciTransport::syncSingleForCPU,
    Rtw89PciTransport::syncSingleForDevice,
};
}

Rtw89PciTransport *Rtw89PciTransport::withDevice(IOPCIDevice *device,
                                                  IOWorkLoop *loop)
{
    auto *transport = new Rtw89PciTransport;
    if (!transport)
        return nullptr;
    if (!transport->initWithDevice(device, loop)) {
        transport->release();
        return nullptr;
    }
    return transport;
}

bool Rtw89PciTransport::initWithDevice(IOPCIDevice *device, IOWorkLoop *loop)
{
    if (!OSObject::init() || !device || !loop || active)
        return false;

    pciDevice = device;
    pciDevice->retain();
    workLoop = loop;
    workLoop->retain();

    dmaLock = IOSimpleLockAlloc();
    pendingLock = IOSimpleLockAlloc();
    if (!dmaLock || !pendingLock)
        return false;

    pciDevice->setBusMasterEnable(true);
    pciDevice->setMemoryEnable(true);

    mmioMap = pciDevice->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2);
    if (!mmioMap)
        return false;
    mmioBaseAddress = reinterpret_cast<volatile void *>(
        mmioMap->getVirtualAddress());
    if (!mmioBaseAddress)
        return false;

    compatDevice = static_cast<struct pci_dev *>(
        IOMallocZero(sizeof(struct pci_dev)));
    if (!compatDevice)
        return false;

    compatDevice->vendor = pciDevice->configRead16(kIOPCIConfigVendorID);
    compatDevice->device = pciDevice->configRead16(kIOPCIConfigDeviceID);
    compatDevice->subsystem_vendor =
        pciDevice->configRead16(kIOPCIConfigSubSystemVendorID);
    compatDevice->subsystem_device =
        pciDevice->configRead16(kIOPCIConfigSubSystemID);
    compatDevice->revision = pciDevice->configRead8(kIOPCIConfigRevisionID);
    compatDevice->kext_dev = this;
    compatDevice->resource[2] =
        reinterpret_cast<resource_size_t>(mmioBaseAddress);
    compatDevice->resource_len[2] = mmioMap->getLength();

    active = this;
    rtw88_pci_io_ops = &pciOperations;
    rtw88_dma_ops = &dmaOperations;
    if (rtw88_compat_init() != 0)
        return false;

    interruptSource = IOInterruptEventSource::interruptEventSource(
        this, &Rtw89PciTransport::interruptOccurred, pciDevice, 0);
    if (!interruptSource || workLoop->addEventSource(interruptSource) !=
                                kIOReturnSuccess)
        return false;
    IOLog("AirportRTW-RTW89: transport ready; interrupt source held disabled\n");
    return true;
}

void Rtw89PciTransport::enableInterrupts()
{
    if (interruptSource && !interruptsEnabled) {
        interruptSource->enable();
        interruptsEnabled = true;
        IOLog("AirportRTW-RTW89: interrupt source enabled\n");
    }
}

void Rtw89PciTransport::disableInterrupts()
{
    if (interruptSource && interruptsEnabled) {
        interruptSource->disable();
        interruptsEnabled = false;
        IOLog("AirportRTW-RTW89: interrupt source disabled\n");
    }
}

void Rtw89PciTransport::free()
{
    teardown();
    OSObject::free();
}

void Rtw89PciTransport::teardown()
{
    if (interruptSource) {
        disableInterrupts();
        if (workLoop)
            workLoop->removeEventSource(interruptSource);
        interruptSource->release();
        interruptSource = nullptr;
    }

    if (active == this) {
        rtw88_compat_exit();
        rtw88_pci_io_ops = nullptr;
        rtw88_dma_ops = nullptr;
        active = nullptr;
    }

    drainPendingFree();
    while (dmaEntries) {
        DMAEntry *entry = dmaEntries;
        dmaEntries = entry->next;
        releaseDMAEntry(entry);
    }

    if (compatDevice) {
        IOFree(compatDevice, sizeof(*compatDevice));
        compatDevice = nullptr;
    }
    if (mmioMap) {
        mmioMap->release();
        mmioMap = nullptr;
        mmioBaseAddress = nullptr;
    }
    if (dmaLock) {
        IOSimpleLockFree(dmaLock);
        dmaLock = nullptr;
    }
    if (pendingLock) {
        IOSimpleLockFree(pendingLock);
        pendingLock = nullptr;
    }
    if (workLoop) {
        workLoop->release();
        workLoop = nullptr;
    }
    if (pciDevice) {
        pciDevice->release();
        pciDevice = nullptr;
    }
}

void Rtw89PciTransport::interruptOccurred(OSObject *owner,
                                           IOInterruptEventSource *source,
                                           int count)
{
    (void)source;
    (void)count;
    auto *transport = OSDynamicCast(Rtw89PciTransport, owner);
    if (transport) {
        __sync_fetch_and_add(&transport->interruptCount, 1);
        rtw88_trigger_interrupt();
        transport->drainPendingFree();
    }
}

void *Rtw89PciTransport::allocateDMA(size_t size,
                                     IOPhysicalAddress *physicalAddress)
{
    auto *descriptor = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        kIOMemoryPhysicallyContiguous | kIODirectionInOut |
            kIOMemoryKernelUserShared,
        size, 0x00000000fffffff0ULL);
    if (!descriptor || descriptor->prepare() != kIOReturnSuccess) {
        if (descriptor)
            descriptor->release();
        return nullptr;
    }

    void *virtualAddress = descriptor->getBytesNoCopy();
    IOPhysicalAddress physical = descriptor->getPhysicalAddress();
    if (!virtualAddress || !physical) {
        descriptor->complete();
        descriptor->release();
        return nullptr;
    }

    auto *entry = static_cast<DMAEntry *>(IOMallocZero(sizeof(DMAEntry)));
    if (!entry) {
        descriptor->complete();
        descriptor->release();
        return nullptr;
    }
    bzero(virtualAddress, size);
    entry->descriptor = descriptor;
    entry->virtualAddress = virtualAddress;
    entry->physicalAddress = physical;
    entry->size = size;

    IOSimpleLockLock(dmaLock);
    entry->next = dmaEntries;
    dmaEntries = entry;
    IOSimpleLockUnlock(dmaLock);
    if (physicalAddress)
        *physicalAddress = physical;
    return virtualAddress;
}

void Rtw89PciTransport::releaseDMAEntry(DMAEntry *entry)
{
    if (!entry)
        return;
    entry->descriptor->complete();
    entry->descriptor->release();
    IOFree(entry, sizeof(*entry));
}

void Rtw89PciTransport::freeDMAByVirtual(void *virtualAddress)
{
    IOSimpleLockLock(dmaLock);
    DMAEntry **cursor = &dmaEntries;
    while (*cursor && (*cursor)->virtualAddress != virtualAddress)
        cursor = &(*cursor)->next;
    DMAEntry *entry = *cursor;
    if (entry)
        *cursor = entry->next;
    IOSimpleLockUnlock(dmaLock);
    if (!entry)
        return;

    if (preemption_enabled()) {
        releaseDMAEntry(entry);
    } else {
        IOSimpleLockLock(pendingLock);
        entry->next = pendingEntries;
        pendingEntries = entry;
        IOSimpleLockUnlock(pendingLock);
    }
}

void Rtw89PciTransport::freeDMAByPhysical(IOPhysicalAddress physicalAddress)
{
    IOSimpleLockLock(dmaLock);
    DMAEntry **cursor = &dmaEntries;
    while (*cursor && (*cursor)->physicalAddress != physicalAddress)
        cursor = &(*cursor)->next;
    DMAEntry *entry = *cursor;
    if (entry)
        *cursor = entry->next;
    IOSimpleLockUnlock(dmaLock);
    if (!entry)
        return;

    if (preemption_enabled()) {
        releaseDMAEntry(entry);
    } else {
        IOSimpleLockLock(pendingLock);
        entry->next = pendingEntries;
        pendingEntries = entry;
        IOSimpleLockUnlock(pendingLock);
    }
}

void Rtw89PciTransport::setDMAOriginal(IOPhysicalAddress physicalAddress,
                                       void *original)
{
    IOSimpleLockLock(dmaLock);
    for (DMAEntry *entry = dmaEntries; entry; entry = entry->next) {
        if (entry->physicalAddress == physicalAddress) {
            entry->originalAddress = original;
            break;
        }
    }
    IOSimpleLockUnlock(dmaLock);
}

void Rtw89PciTransport::syncDMAForCPU(IOPhysicalAddress physicalAddress,
                                      size_t size)
{
    IOSimpleLockLock(dmaLock);
    for (DMAEntry *entry = dmaEntries; entry; entry = entry->next) {
        if (entry->physicalAddress == physicalAddress &&
            entry->originalAddress) {
            void *destination = entry->originalAddress;
            void *source = entry->virtualAddress;
            const size_t length = size < entry->size ? size : entry->size;
            IOSimpleLockUnlock(dmaLock);
            memcpy(destination, source, length);
            return;
        }
    }
    IOSimpleLockUnlock(dmaLock);
}

void Rtw89PciTransport::syncDMAForDevice(IOPhysicalAddress physicalAddress,
                                         size_t size)
{
    IOSimpleLockLock(dmaLock);
    for (DMAEntry *entry = dmaEntries; entry; entry = entry->next) {
        if (entry->physicalAddress == physicalAddress &&
            entry->originalAddress) {
            void *destination = entry->virtualAddress;
            void *source = entry->originalAddress;
            const size_t length = size < entry->size ? size : entry->size;
            IOSimpleLockUnlock(dmaLock);
            memcpy(destination, source, length);
            return;
        }
    }
    IOSimpleLockUnlock(dmaLock);
}

void Rtw89PciTransport::drainPendingFree()
{
    if (!pendingLock || !preemption_enabled())
        return;
    IOSimpleLockLock(pendingLock);
    DMAEntry *entries = pendingEntries;
    pendingEntries = nullptr;
    IOSimpleLockUnlock(pendingLock);
    while (entries) {
        DMAEntry *next = entries->next;
        releaseDMAEntry(entries);
        entries = next;
    }
}

int Rtw89PciTransport::readConfigByte(struct pci_dev *, int offset,
                                      unsigned char *value)
{
    if (!active || !value)
        return -1;
    *value = active->pciDevice->configRead8(offset);
    return 0;
}

int Rtw89PciTransport::readConfigWord(struct pci_dev *, int offset,
                                      unsigned short *value)
{
    if (!active || !value)
        return -1;
    *value = active->pciDevice->configRead16(offset);
    return 0;
}

int Rtw89PciTransport::readConfigDword(struct pci_dev *, int offset,
                                       unsigned int *value)
{
    if (!active || !value)
        return -1;
    *value = active->pciDevice->configRead32(offset);
    return 0;
}

int Rtw89PciTransport::writeConfigByte(struct pci_dev *, int offset,
                                       unsigned char value)
{
    if (!active)
        return -1;
    active->pciDevice->configWrite8(offset, value);
    return 0;
}

int Rtw89PciTransport::writeConfigWord(struct pci_dev *, int offset,
                                       unsigned short value)
{
    if (!active)
        return -1;
    active->pciDevice->configWrite16(offset, value);
    return 0;
}

int Rtw89PciTransport::writeConfigDword(struct pci_dev *, int offset,
                                        unsigned int value)
{
    if (!active)
        return -1;
    active->pciDevice->configWrite32(offset, value);
    return 0;
}

void *Rtw89PciTransport::mapBAR(struct pci_dev *, int bar, size_t)
{
    return active && bar == 2 ? (void *)active->mmioBaseAddress : nullptr;
}

void Rtw89PciTransport::unmapBAR(struct pci_dev *, void *) {}
int Rtw89PciTransport::enableMSI(struct pci_dev *) { return active ? 0 : -1; }
void Rtw89PciTransport::disableMSI(struct pci_dev *) {}

int Rtw89PciTransport::findCapability(struct pci_dev *, int capability)
{
    if (!active)
        return 0;
    UInt8 offset = 0;
    return active->pciDevice->findPCICapability(capability, &offset)
        ? offset : 0;
}

void *Rtw89PciTransport::allocateCoherent(struct device *, size_t size,
                                           unsigned long *dma,
                                           unsigned int)
{
    IOPhysicalAddress physical = 0;
    void *memory = active ? active->allocateDMA(size, &physical) : nullptr;
    if (dma)
        *dma = physical;
    return memory;
}

void Rtw89PciTransport::freeCoherent(struct device *, size_t, void *memory,
                                      unsigned long)
{
    if (active)
        active->freeDMAByVirtual(memory);
}

unsigned long Rtw89PciTransport::mapSingle(struct device *, void *memory,
                                           size_t size, int direction)
{
    if (!active || !memory)
        return 0;
    IOPhysicalAddress physical = 0;
    void *bounce = active->allocateDMA(size, &physical);
    if (!bounce)
        return 0;
    active->setDMAOriginal(physical, memory);
    if (direction == DMA_TO_DEVICE || direction == DMA_BIDIRECTIONAL)
        memcpy(bounce, memory, size);
    return physical;
}

void Rtw89PciTransport::unmapSingle(struct device *, unsigned long dma,
                                    size_t size, int direction)
{
    if (!active)
        return;

    /* dma_unmap_single() is a CPU ownership boundary.  Some rtw89 paths
     * explicitly sync persistent RX buffers, while teardown/error paths rely
     * on unmap itself.  Preserve Linux DMA semantics by copying a streaming
     * receive/bidirectional bounce buffer back before releasing it. */
    if (direction == DMA_FROM_DEVICE || direction == DMA_BIDIRECTIONAL)
        active->syncDMAForCPU(dma, size);
    active->freeDMAByPhysical(dma);
}

void Rtw89PciTransport::syncSingleForCPU(struct device *,
                                         unsigned long dma,
                                         size_t size, int direction)
{
    if (active &&
        (direction == DMA_FROM_DEVICE || direction == DMA_BIDIRECTIONAL))
        active->syncDMAForCPU(dma, size);
}

void Rtw89PciTransport::syncSingleForDevice(struct device *,
                                            unsigned long dma, size_t size,
                                            int direction)
{
    if (active &&
        (direction == DMA_TO_DEVICE || direction == DMA_BIDIRECTIONAL))
        active->syncDMAForDevice(dma, size);
}
