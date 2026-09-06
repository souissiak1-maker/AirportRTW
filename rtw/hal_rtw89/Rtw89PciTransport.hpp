/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef Rtw89PciTransport_hpp
#define Rtw89PciTransport_hpp

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSObject.h>

struct pci_dev;
struct device;

/*
 * IOKit transport used by the Linux-derived rtw89 PCI core.  The driver is
 * single-device, like the existing Intel HALs, so the C compatibility hooks
 * are installed for this object's lifetime.
 */
class Rtw89PciTransport final : public OSObject {
    OSDeclareDefaultStructors(Rtw89PciTransport)

public:
    static Rtw89PciTransport *withDevice(IOPCIDevice *device,
                                         IOWorkLoop *workLoop);
    bool initWithDevice(IOPCIDevice *device, IOWorkLoop *workLoop);
    void free() override;

    struct pci_dev *linuxDevice() const { return compatDevice; }
    volatile void *mmioBase() const { return mmioBaseAddress; }

    void enableInterrupts();
    void disableInterrupts();
    void drainPendingFree();
    UInt64 getInterruptCount() const { return interruptCount; }

private:
    struct DMAEntry {
        IOBufferMemoryDescriptor *descriptor;
        void *virtualAddress;
        IOPhysicalAddress physicalAddress;
        size_t size;
        void *originalAddress;
        DMAEntry *next;
    };

    static void interruptOccurred(OSObject *owner,
                                  IOInterruptEventSource *source, int count);

public: /* C compatibility operation tables */
    static int readConfigByte(struct pci_dev *, int, unsigned char *);
    static int readConfigWord(struct pci_dev *, int, unsigned short *);
    static int readConfigDword(struct pci_dev *, int, unsigned int *);
    static int writeConfigByte(struct pci_dev *, int, unsigned char);
    static int writeConfigWord(struct pci_dev *, int, unsigned short);
    static int writeConfigDword(struct pci_dev *, int, unsigned int);
    static void *mapBAR(struct pci_dev *, int, size_t);
    static void unmapBAR(struct pci_dev *, void *);
    static int enableMSI(struct pci_dev *);
    static void disableMSI(struct pci_dev *);
    static int findCapability(struct pci_dev *, int);

    static void *allocateCoherent(struct device *, size_t,
                                  unsigned long *, unsigned int);
    static void freeCoherent(struct device *, size_t, void *,
                             unsigned long);
    static unsigned long mapSingle(struct device *, void *, size_t, int);
    static void unmapSingle(struct device *, unsigned long, size_t, int);
    static void syncSingleForCPU(struct device *, unsigned long,
                                 size_t, int);
    static void syncSingleForDevice(struct device *, unsigned long,
                                    size_t, int);

private:

    void *allocateDMA(size_t size, IOPhysicalAddress *physicalAddress);
    void freeDMAByVirtual(void *virtualAddress);
    void freeDMAByPhysical(IOPhysicalAddress physicalAddress);
    void setDMAOriginal(IOPhysicalAddress physicalAddress, void *original);
    void syncDMAForCPU(IOPhysicalAddress physicalAddress, size_t size);
    void syncDMAForDevice(IOPhysicalAddress physicalAddress, size_t size);
    void releaseDMAEntry(DMAEntry *entry);
    void teardown();

    static Rtw89PciTransport *active;

    IOPCIDevice *pciDevice {nullptr};
    IOWorkLoop *workLoop {nullptr};
    IOMemoryMap *mmioMap {nullptr};
    volatile void *mmioBaseAddress {nullptr};
    IOInterruptEventSource *interruptSource {nullptr};
    bool interruptsEnabled {false};
    volatile UInt64 interruptCount {0};
    struct pci_dev *compatDevice {nullptr};

    IOSimpleLock *dmaLock {nullptr};
    IOSimpleLock *pendingLock {nullptr};
    DMAEntry *dmaEntries {nullptr};
    DMAEntry *pendingEntries {nullptr};
};

#endif /* Rtw89PciTransport_hpp */
