//
//  AirportRTWV2.cpp
//  AirportRTW-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#include "AirportRTWNativeController.hpp"
#include <sys/_netstat.h>
#include <crypto/sha1.h>
#include <net80211/ieee80211_priv.h>
#include <net80211/ieee80211_var.h>

#include "AirportRTWNativeInterface.hpp"
#include "IOPCIEDeviceWrapper.hpp"

#define super IO80211Controller
OSDefineMetaClassAndStructors(AirportRTW, IO80211Controller);
OSDefineMetaClassAndStructors(CTimeout, OSObject)

IO80211WorkQueue *_fWorkloop;
IOCommandGate *_fCommandGate;

void AirportRTW::releaseAll()
{
#ifdef AIRPORT_WCL
    if (fNetIf)
        static_cast<AirportRTWSkywalkInterface *>(fNetIf)->stopWCL();
    OSSafeReleaseNULL(driverFaultReporter);
    OSSafeReleaseNULL(driverCoreFaultReporter);
    OSSafeReleaseNULL(driverFaultStream);
    OSSafeReleaseNULL(driverLogger);
    // Stop only successfully started pipes, while their owner workloop exists.
    if (driverSnapshotsPipeStarted) {
        driverSnapshotsPipe->CCPipe::stopPipe();
        driverSnapshotsPipeStarted = false;
    }
    if (driverDataPathPipeStarted) {
        driverDataPathPipe->CCPipe::stopPipe();
        driverDataPathPipeStarted = false;
    }
    if (driverLogPipeStarted) {
        driverLogPipe->CCPipe::stopPipe();
        driverLogPipeStarted = false;
    }
#endif
    OSSafeReleaseNULL(driverLogPipe);
    OSSafeReleaseNULL(driverDataPathPipe);
    OSSafeReleaseNULL(driverSnapshotsPipe);
#ifndef AIRPORT_WCL
    OSSafeReleaseNULL(driverFaultReporter);
#endif
    if (fHalService) {
        fHalService->release();
        fHalService = NULL;
    }
    if (_fWorkloop) {
        if (_fCommandGate) {
//            _fCommandGate->disable();
            _fWorkloop->removeEventSource(_fCommandGate);
            _fCommandGate->release();
            _fCommandGate = NULL;
        }
        if (scanSource) {
            scanSource->cancelTimeout();
            scanSource->disable();
            _fWorkloop->removeEventSource(scanSource);
            scanSource->release();
            scanSource = NULL;
        }
        if (fWatchdogWorkLoop && watchdogTimer) {
            watchdogTimer->cancelTimeout();
            fWatchdogWorkLoop->removeEventSource(watchdogTimer);
            watchdogTimer->release();
            watchdogTimer = NULL;
            fWatchdogWorkLoop->release();
            fWatchdogWorkLoop = NULL;
        }
        _fWorkloop->release();
        _fWorkloop = NULL;
    }
    unregistPM();
}

void AirportRTW::
eventHandler(struct ieee80211com *ic, int msgCode, void *data)
{
    AirportRTW *that = OSDynamicCast(AirportRTW, ic->ic_ac.ac_if.controller);
#ifdef AIRPORT_WCL
    if (!that)
        return;
#endif
    IO80211SkywalkInterface *interface = that->fNetIf;
    if (!interface)
        return;
#ifdef AIRPORT_WCL
    static_cast<AirportRTWSkywalkInterface *>(interface)->handleWCLEvent(msgCode, data);
#else
    switch (msgCode) {
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            interface->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, NULL, 0, 0);
            break;
        case IEEE80211_EVT_STA_ASSOC_DONE:
            interface->postMessage(APPLE80211_M_ASSOC_DONE, NULL, 0, 0);
            break;
        case IEEE80211_EVT_STA_DEAUTH:
            interface->postMessage(APPLE80211_M_DEAUTH_RECEIVED, NULL, 0, 0);
            break;
        default:
            break;
    }
#endif
}

void AirportRTW::watchdogAction(IOTimerEventSource *timer)
{
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    (*ifp->if_watchdog)(ifp);

    watchdogTimer->setTimeoutMS(kWatchDogTimerPeriod);
}

void AirportRTW::fakeScanDone(OSObject *owner, IOTimerEventSource *sender)
{
#ifndef AIRPORT_WCL
    UInt32 msg = 0;
#endif
    AirportRTW *that = (AirportRTW *)owner;
#ifdef AIRPORT_WCL
    if (that->fNetIf)
        static_cast<AirportRTWSkywalkInterface *>(that->fNetIf)->completeWCLScan();
#else
    that->fNetIf->postMessage(APPLE80211_M_SCAN_DONE, &msg, 4, 0);
#endif
}

bool AirportRTW::init(OSDictionary *properties)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    bool ret = super::init(properties);
    awdlSyncEnable = true;
    power_state = 0;
    memset(geo_location_cc, 0, sizeof(geo_location_cc));
    return ret;
}

IOService* AirportRTW::probe(IOService *provider, SInt32 *score)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    IOPCIEDeviceWrapper *wrapper = OSDynamicCast(IOPCIEDeviceWrapper, provider);
    if (!wrapper) {
        XYLog("%s Not a IOPCIEDeviceWrapper instance\n", __FUNCTION__);
        return NULL;
    }
    pciNub = wrapper->pciNub;
    fHalService = wrapper->fHalService;
    if (!pciNub || !fHalService) {
        XYLog("%s Not a valid IOPCIEDeviceWrapper instance\n", __FUNCTION__);
        return NULL;
    }
    return super::probe(provider, score);
}

#define LOWER32(x)  ((uint64_t)(x) & 0xffffffff)
#define HIGHER32(x) ((uint64_t)(x) >> 32)

bool AirportRTW::
initCCLogs()
{
    CCPipeOptions driverLogOptions = { 0 };
    driverLogOptions.pipe_type = 0;
    driverLogOptions.log_data_type = 1;
    driverLogOptions.pipe_size = 0x200000;
    driverLogOptions.min_log_size_notify = 0xccccc;
    driverLogOptions.notify_threshold = 1000;
    strlcpy(driverLogOptions.file_name, "Itlwm_Logs", sizeof(driverLogOptions.file_name));
    snprintf(driverLogOptions.name, sizeof(driverLogOptions.name), "wlan%d", 0);
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pad9 = 0x1000000;
    driverLogOptions.pad10 = 2;
    driverLogOptions.file_options = 0;
    driverLogOptions.log_policy = 0;
    driverLogPipe = CCPipe::withOwnerNameCapacity(this, "com.senmiko.AirportRTW", "DriverLogs", &driverLogOptions);
    XYLog("%s driverLogPipeRet %d\n", __FUNCTION__, driverLogPipe != NULL);
#ifdef AIRPORT_WCL
    if (!driverLogPipe || !getWorkLoop()) {
        RTW_LOG("AirportRTW: CoreCapture DriverLogs allocation/workloop failed\n");
        return false;
    }
    // The factory only initializes the pipe. startPipe creates its event sources.
    // Qualify the native method: do not dispatch through the legacy CCPipe header.
    driverLogPipeStarted = driverLogPipe->CCPipe::startPipe();
    if (!driverLogPipeStarted) {
        RTW_LOG("AirportRTW: CoreCapture DriverLogs startPipe failed\n");
        return false;
    }
    CCStreamOptions loggerOptions = {};
    CCStream *logger = CCStream::withPipeAndName(driverLogPipe, "AirportRTW", &loggerOptions);
    driverLogger = OSDynamicCast(CCLogStream, logger);
    if (!driverLogger) {
        RTW_LOG("AirportRTW: CoreCapture DriverLogs stream cast failed\n");
        OSSafeReleaseNULL(logger);
        return false;
    }
#endif

    memset(&driverLogOptions, 0, sizeof(driverLogOptions));
    driverLogOptions.pipe_type = 0;
    driverLogOptions.log_data_type = 0;
    driverLogOptions.pipe_size = 0x200000;
    driverLogOptions.min_log_size_notify = 0xccccc;
    driverLogOptions.notify_threshold = 1000;
    strlcpy(driverLogOptions.file_name, "AppleBCMWLAN_Datapath", sizeof(driverLogOptions.file_name));
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pad9 = HIGHER32(0x202800000);
    driverLogOptions.pad10 = LOWER32(0x202800000);
    driverLogOptions.file_options = 0;
    driverLogOptions.log_policy = 0;
    driverDataPathPipe = CCPipe::withOwnerNameCapacity(this, "com.senmiko.AirportRTW", "DatapathEvents", &driverLogOptions);
    XYLog("%s driverDataPathPipeRet %d\n", __FUNCTION__, driverDataPathPipe != NULL);
#ifdef AIRPORT_WCL
    if (!driverDataPathPipe) {
        RTW_LOG("AirportRTW: CoreCapture DatapathEvents allocation failed\n");
        return false;
    }
    driverDataPathPipeStarted = driverDataPathPipe->CCPipe::startPipe();
    if (!driverDataPathPipeStarted) {
        RTW_LOG("AirportRTW: CoreCapture DatapathEvents startPipe failed\n");
        return false;
    }
#endif

    memset(&driverLogOptions, 0, sizeof(driverLogOptions));
    driverLogOptions.pipe_type = 0x200000001;
    driverLogOptions.log_data_type = 2;
    strlcpy(driverLogOptions.file_name, "StateSnapshots", sizeof(driverLogOptions.file_name));
    strlcpy(driverLogOptions.name, "0", sizeof(driverLogOptions.name));
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pipe_size = 128;
    driverSnapshotsPipe = CCPipe::withOwnerNameCapacity(this, "com.senmiko.AirportRTW", "StateSnapshots", &driverLogOptions);
    XYLog("%s driverSnapshotsPipeRet %d\n", __FUNCTION__, driverSnapshotsPipe != NULL);
#ifdef AIRPORT_WCL
    if (!driverSnapshotsPipe) {
        RTW_LOG("AirportRTW: CoreCapture StateSnapshots allocation failed\n");
        return false;
    }
    driverSnapshotsPipeStarted = driverSnapshotsPipe->CCPipe::startPipe();
    if (!driverSnapshotsPipeStarted) {
        RTW_LOG("AirportRTW: CoreCapture StateSnapshots startPipe failed\n");
        return false;
    }
#endif

    CCStreamOptions faultReportOptions = { 0 };
    faultReportOptions.stream_type = 1;
    faultReportOptions.console_level = 0xFFFFFFFFFFFFFFFF;
#ifdef AIRPORT_WCL
    driverFaultStream = CCStream::withPipeAndName(driverSnapshotsPipe, "FaultReporter", &faultReportOptions);
    CCDataStream *dataStream = OSDynamicCast(CCDataStream, driverFaultStream);
    if (!dataStream || !_fWorkloop) {
        RTW_LOG("AirportRTW: CoreCapture FaultReporter data stream/workloop failed\n");
        return false;
    }
    driverCoreFaultReporter = CCFaultReporter::withStreamWorkloop(dataStream, _fWorkloop);
    if (!driverCoreFaultReporter) {
        RTW_LOG("AirportRTW: CoreCapture CCFaultReporter factory failed\n");
        return false;
    }
    driverFaultReporter = IO80211FaultReporter::allocWithParams(driverCoreFaultReporter);
    if (!OSDynamicCast(CommonFaultReporter, driverFaultReporter)) {
        RTW_LOG("AirportRTW: CoreCapture IO80211FaultReporter factory/cast failed\n");
        return false;
    }
#else
    driverFaultReporter = CCStream::withPipeAndName(driverSnapshotsPipe, "FaultReporter", &faultReportOptions);
#endif
    RTW_LOG("AirportRTW: CoreCapture setup complete\n");
    XYLog("%s driverFaultReporterRet %d\n", __FUNCTION__, driverFaultReporter != NULL);
    return driverLogPipe && driverDataPathPipe && driverSnapshotsPipe && driverFaultReporter;
}

bool AirportRTW::start(IOService *provider)
{
    // Record progress on the PCI wrapper: it survives controller start failure,
    // unlike properties on this controller or the finite kernel log buffer.
    auto stage = [provider](const char *name) {
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupStage", name));
        RTW_LOG("AirportRTW: startup stage: %s\n", name);
    };
    RTW_DIAGNOSTIC(provider->setProperty("RTWStartupDiagnostics", "Tahoe-startup-v2"));
    RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanFalse));
    stage("OS version check");
#if __IO80211_TARGET == __MAC_15_2
    if (version_major != 24 || version_minor < 2) {
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
#elif __IO80211_TARGET == __MAC_26_0
    if (version_major != 25) {
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
#endif
    XYLog("%s\n", __PRETTY_FUNCTION__);
    struct IOSkywalkEthernetInterface::RegistrationInfo registInfo;
    int boot_value = 0;

    UInt8 builtIn = 0;
    setProperty("built-in", OSData::withBytes(&builtIn, sizeof(builtIn)));
    setProperty("DriverKitDriver", kOSBooleanFalse);
#ifdef AIRPORT_WCL
    stage("CoreCapture setup");
    if (!initCCLogs()) {
        RTW_LOG("AirportRTW: controller startup stopped by CoreCapture failure\n");
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
#endif
    stage("IO80211Controller::start");
    if (!super::start(provider)) {
#ifdef AIRPORT_WCL
        releaseAll();
#endif
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("PCI device setup");
    pciNub->setBusMasterEnable(true);
    pciNub->setIOEnable(true);
    pciNub->setMemoryEnable(true);
    pciNub->configWrite8(0x41, 0);
    stage("PCI power domain");
    if (pciNub->requestPowerDomainState(kIOPMPowerOn,
                                        (IOPowerConnection *) getParentEntry(gIOPowerPlane), IOPMLowestState) != IOPMNoErr) {
        super::stop(provider);
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("PCI power management");
    if (initPCIPowerManagment(pciNub) == false) {
        super::stop(pciNub);
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("workqueue availability");
    if (_fWorkloop == NULL) {
        XYLog("No _fWorkloop!!\n");
        super::stop(pciNub);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("command gate creation");
    _fCommandGate = IOCommandGate::commandGate(this, (IOCommandGate::Action)AirportRTW::tsleepHandler);
    if (_fCommandGate == 0) {
        XYLog("No command gate!!\n");
        super::stop(pciNub);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("command gate registration");
    _fWorkloop->addEventSource(_fCommandGate);
    const IONetworkMedium *primaryMedium;
    stage("network medium setup");
    if (!createMediumTables(&primaryMedium) ||
        !setCurrentMedium(primaryMedium) || !setSelectedMedium(primaryMedium)) {
        XYLog("setup medium fail\n");
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("HAL controller initialization");
    fHalService->initWithController(this, _fWorkloop, _fCommandGate);

    if (PE_parse_boot_argn("-novht", &boot_value, sizeof(boot_value)))
        fHalService->get80211Controller()->ic_userflags |= IEEE80211_F_NOVHT;
    if (PE_parse_boot_argn("-noht40", &boot_value, sizeof(boot_value)))
        fHalService->get80211Controller()->ic_userflags |= IEEE80211_F_NOHT40;

    stage("Realtek HAL attach");
    if (!fHalService->attach(pciNub)) {
        XYLog("attach fail\n");
        super::stop(pciNub);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    // attachNet80211() zeroes ieee80211com during HAL attach. Install the
    // native event bridge afterwards or beacon/scan-done and lifecycle events
    // are silently lost even though hardware scanning populates the cache.
    fHalService->get80211Controller()->ic_event_handler = eventHandler;
    RTW_DIAGNOSTIC(setProperty("RTWWCLEventBridgeInstalled", kOSBooleanTrue));
    stage("watchdog workloop");
    fWatchdogWorkLoop = IOWorkLoop::workLoop();
    if (fWatchdogWorkLoop == NULL) {
        XYLog("init watchdog workloop fail\n");
        fHalService->detach(pciNub);
        super::stop(pciNub);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("watchdog timer");
    watchdogTimer = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &AirportRTW::watchdogAction));
    if (!watchdogTimer) {
        XYLog("init watchdog fail\n");
        fHalService->detach(pciNub);
        super::stop(pciNub);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    fWatchdogWorkLoop->addEventSource(watchdogTimer);
    stage("scan timer");
    scanSource = IOTimerEventSource::timerEventSource(this, &fakeScanDone);
#ifdef AIRPORT_WCL
    if (!scanSource || _fWorkloop->addEventSource(scanSource) != kIOReturnSuccess) {
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
#else
    _fWorkloop->addEventSource(scanSource);
#endif
    scanSource->enable();

    stage("Skywalk interface allocation/init");
    fNetIf = new AirportRTWSkywalkInterface;
#ifdef AIRPORT_WCL
    if (!fNetIf || !static_cast<AirportRTWSkywalkInterface *>(fNetIf)->init(this)) {
#else
    if (!fNetIf->init(this)) {
#endif
        XYLog("Skywalk interface init fail\n");
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("Skywalk interface role");
    fNetIf->setInterfaceRole(1);
    fNetIf->setInterfaceId(1);

#ifndef AIRPORT_WCL
    stage("CoreCapture setup");
    if (!initCCLogs()) {
        XYLog("CCLog init fail\n");
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
#endif
    stage("Skywalk service attach");
    if (!fNetIf->attach(this)) {
        XYLog("attach to service fail\n");
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("IO80211 interface attach");
    if (!attachInterface(fNetIf, this)) {
        XYLog("attach to interface fail\n");
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("BSD interface attach");
    if (!IONetworkController::attachInterface((IONetworkInterface **)&bsdInterface,
#ifdef AIRPORT_WCL
                                             false
#else
                                             true
#endif
                                             )) {
        XYLog("attach to IONetworkController interface fail\n");
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    memset(&registInfo, 0, sizeof(registInfo));
    stage("Skywalk registration info");
    if (!fNetIf->initRegistrationInfo(&registInfo, 1, sizeof(registInfo))) {
        XYLog("initRegistrationInfo fail\n");
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
#ifdef AIRPORT_WCL
    stage("Skywalk registration storage");
    fNetIf->mExpansionData->fRegistrationInfo = (struct IOSkywalkNetworkInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkNetworkInterface::RegistrationInfo));
    fNetIf->mExpansionData2->fRegistrationInfo = (struct IOSkywalkEthernetInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkEthernetInterface::RegistrationInfo));
    if (!fNetIf->mExpansionData->fRegistrationInfo || !fNetIf->mExpansionData2->fRegistrationInfo) {
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    memcpy(fNetIf->mExpansionData->fRegistrationInfo, &registInfo, sizeof(registInfo));
    memcpy(fNetIf->mExpansionData2->fRegistrationInfo, &registInfo, sizeof(registInfo));
    if (fNetIf->getInterfaceRole() == 1)
        fNetIf->deferBSDAttach(true);
    stage("Skywalk interface start");
    if (!fNetIf->start(this)) {
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }

#else
    stage("Skywalk registration info");
    if (!fNetIf->initRegistrationInfo(&registInfo, 1, sizeof(registInfo))) {
        XYLog("initRegistrationInfo fail\n");
        super::stop(provider);
        releaseAll();
        RTW_DIAGNOSTIC(provider->setProperty("RTWStartupFailed", kOSBooleanTrue));
        return false;
    }
    stage("Skywalk registration storage");
    fNetIf->mExpansionData->fRegistrationInfo = (struct IOSkywalkNetworkInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkNetworkInterface::RegistrationInfo));
    fNetIf->mExpansionData2->fRegistrationInfo = (struct IOSkywalkEthernetInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkEthernetInterface::RegistrationInfo));
    memcpy(fNetIf->mExpansionData->fRegistrationInfo, &registInfo, sizeof(registInfo));
    memcpy(fNetIf->mExpansionData2->fRegistrationInfo, &registInfo, sizeof(registInfo));
    if (fNetIf->getInterfaceRole() == 1)
        fNetIf->deferBSDAttach(true);
    fNetIf->start(this);

#endif
    stage("link status initialization");
    setLinkStatus(kIONetworkLinkValid);
    if (TAILQ_EMPTY(&fHalService->get80211Controller()->ic_ess))
        fHalService->get80211Controller()->ic_flags |= IEEE80211_F_AUTO_JOIN;
#ifdef AIRPORT_WCL
    stage("BSD interface publication");
    bsdInterface->registerService();
#endif
    stage("controller publication");
    registerService();
    stage("controller startup complete");
    return true;
}

void AirportRTW::stop(IOService *provider)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);XYLog("%s\n", __PRETTY_FUNCTION__);
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
#ifdef AIRPORT_WCL
    if (fNetIf)
        static_cast<AirportRTWSkywalkInterface *>(fNetIf)->stopWCL();
#endif
    super::stop(provider);
    disableAdapter(bsdInterface);
    setLinkStatus(kIONetworkLinkValid);
    fHalService->detach(pciNub);
    ether_ifdetach(ifp);
    detachInterface(fNetIf, true);
    OSSafeReleaseNULL(fNetIf);
    releaseAll();
}

void AirportRTW::free()
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    if (fHalService != NULL) {
        fHalService->release();
        fHalService = NULL;
    }
    if (syncFrameTemplate != NULL && syncFrameTemplateLength > 0) {
        IOFree(syncFrameTemplate, syncFrameTemplateLength);
        syncFrameTemplateLength = 0;
        syncFrameTemplate = NULL;
    }
    if (roamProfile != NULL) {
        IOFree(roamProfile, sizeof(struct apple80211_roam_profile_band_data));
        roamProfile = NULL;
    }
    if (btcProfile != NULL) {
        IOFree(btcProfile, sizeof(struct apple80211_btc_profiles_data));
        btcProfile = NULL;
    }
    super::free();
}

bool AirportRTW::createWorkQueue()
{
    XYLog("%s %d\n", __FUNCTION__, _fWorkloop != 0);
    return _fWorkloop != 0;
}

IO80211WorkQueue *AirportRTW::getWorkQueue()
#ifdef AIRPORT_WCL
const
#endif
{
    return _fWorkloop;
}

#ifdef AIRPORT_WCL
CommonFaultReporter *AirportRTW::getFaultReporterFromDriver()
#else
void *AirportRTW::getFaultReporterFromDriver()
#endif
{
    return driverFaultReporter;
}

IOReturn AirportRTW::enable(IO80211SkywalkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    super::enable(netif);
    _fCommandGate->enable();
    if (power_state)
        enableAdapter(bsdInterface);
    return kIOReturnSuccess;
}

IOReturn AirportRTW::disable(IO80211SkywalkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    super::disable(netif);
    setLinkStatus(kIONetworkLinkValid);
    return kIOReturnSuccess;
}

bool AirportRTW::configureInterface(IONetworkInterface *netif)
{
    IONetworkData *nd;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;

    if (super::configureInterface(netif) == false) {
        XYLog("super failed\n");
        return false;
    }

    nd = netif->getParameter(kIONetworkStatsKey);
    if (!nd || !(fpNetStats = (IONetworkStats *)nd->getBuffer())) {
        XYLog("network statistics buffer unavailable?\n");
        return false;
    }
    ifp->netStat = fpNetStats;
    ether_ifattach(ifp, OSDynamicCast(IOEthernetInterface, netif));
    fpNetStats->collisions = 0;
#ifdef __PRIVATE_SPI__
    netif->configureOutputPullModel(fHalService->getDriverInfo()->getTxQueueSize(), 0, 0, IOEthernetInterface::kOutputPacketSchedulingModelNormal, 0);
#endif

    return true;
}

IONetworkInterface *AirportRTW::createInterface()
{
    AirportRTWEthernetInterface *netif = new AirportRTWEthernetInterface;
    if (!netif)
        return NULL;
    if (!netif->initWithSkywalkInterfaceAndProvider(this, fNetIf)) {
        netif->release();
        return NULL;
    }
    return netif;
}

bool AirportRTW::createMediumTables(const IONetworkMedium **primary)
{
    IONetworkMedium    *medium;

    OSDictionary *mediumDict = OSDictionary::withCapacity(2);
    if (mediumDict == NULL) {
        XYLog("Cannot allocate OSDictionary\n");
        return false;
    }

    medium = IONetworkMedium::medium(kIOMediumIEEE80211, 54000000);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();
    if (primary) {
        *primary = medium;
    }
    medium = IONetworkMedium::medium(kIOMediumIEEE80211None, 0);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();

    bool result = publishMediumDictionary(mediumDict);
    if (!result) {
        XYLog("Cannot publish medium dictionary!\n");
    }

    mediumDict->release();
    return result;
}

IOReturn AirportRTW::selectMedium(const IONetworkMedium *medium) {
    setSelectedMedium(medium);
    return kIOReturnSuccess;
}

bool AirportRTW::
setLinkStatus(UInt32 status, const IONetworkMedium * activeMedium, UInt64 speed, OSData * data)
{
    struct _ifnet *ifq = &fHalService->get80211Controller()->ic_ac.ac_if;
    if (status == currentStatus) {
        return true;
    }
    bool ret = super::setLinkStatus(status, activeMedium, speed, data);
    currentStatus = status;
    if (fNetIf) {
        if (status & kIONetworkLinkActive) {
#ifdef __PRIVATE_SPI__
            bsdInterface->startOutputThread();
#endif
            getCommandGate()->runAction(setLinkStateGated, (void *)kIO80211NetworkLinkUp, (void *)0);
//            fNetIf->setLinkQualityMetric(100);
        } else if (!(status & kIONetworkLinkNoNetworkChange)) {
#ifdef __PRIVATE_SPI__
            bsdInterface->stopOutputThread();
            bsdInterface->flushOutputQueue();
#endif
            ifq_flush(&ifq->if_snd);
            mq_purge(&fHalService->get80211Controller()->ic_mgtq);
            getCommandGate()->runAction(setLinkStateGated, (void *)kIO80211NetworkLinkDown, (void *)fHalService->get80211Controller()->ic_deauth_reason);
        }
    }
    return ret;
}

IOReturn AirportRTW::
setLinkStateGated(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    AirportRTW *that = OSDynamicCast(AirportRTW, target);
#ifdef AIRPORT_WCL
    that->bsdInterface->setLinkState((IO80211LinkState)(uint64_t)arg0);
    static_cast<AirportRTWSkywalkInterface *>(that->fNetIf)->handleWCLLink(
        (IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp);
    return kIOReturnSuccess;
#else
    IOReturn ret = that->fNetIf->setLinkState((IO80211LinkState)(uint64_t)arg0, (unsigned int)(uint64_t)arg1);
    that->fNetIf->setRunningState((IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp);
    that->fNetIf->postMessage(APPLE80211_M_LINK_CHANGED, NULL, 0, false);
    that->fNetIf->postMessage(APPLE80211_M_BSSID_CHANGED, NULL, 0, false);
    that->fNetIf->postMessage(APPLE80211_M_SSID_CHANGED, NULL, 0, false);
    if ((IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp) {
        that->fNetIf->reportLinkStatus(3, 0x80);
    } else {
        that->fNetIf->reportLinkStatus(1, 0);
    }
    that->bsdInterface->setLinkState((IO80211LinkState)(uint64_t)arg0);
    return ret;
#endif
}

#ifdef __PRIVATE_SPI__
IOReturn AirportRTW::outputStart(IONetworkInterface *interface, IOOptionBits options)
{
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    mbuf_t m = NULL;
    if (ifq_is_oactive(&ifp->if_snd))
        return kIOReturnNoResources;
    while (kIOReturnSuccess == interface->dequeueOutputPackets(1, &m)) {
        if (outputPacket(m, NULL)!= kIOReturnOutputSuccess ||
            ifq_is_oactive(&ifp->if_snd))
            return kIOReturnNoResources;
    }
    return kIOReturnSuccess;
}

IOReturn AirportRTW::networkInterfaceNotification(
                    IONetworkInterface * interface,
                    uint32_t              type,
                    void *                  argument )
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}
#endif

extern const char* hexdump(uint8_t *buf, size_t len);

#ifdef AIRPORT_WCL
UInt32 AirportRTW::outputPacket(mbuf_t m, void *param)
{
//    XYLog("%s\n", __FUNCTION__);
    IOReturn ret = kIOReturnOutputSuccess;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;

    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || ifp->if_snd.queue == NULL) {
        if (m && mbuf_type(m) != MBUF_TYPE_FREE)
            freePacket(m);
        return kIOReturnOutputDropped;
    }
    if (!m || mbuf_type(m) == MBUF_TYPE_FREE) {
        ifp->netStat->outputErrors++;
        return kIOReturnOutputDropped;
    }
    if (!(mbuf_flags(m) & MBUF_PKTHDR)) {
        ifp->netStat->outputErrors++;
        freePacket(m);
        return kIOReturnOutputDropped;
    }
    if (!ifp->if_snd.queue->lockEnqueue(m)) {
        freePacket(m);
        ret = kIOReturnOutputDropped;
    }
    (*ifp->if_start)(ifp);
    return ret;
}
#else
UInt32 AirportRTW::outputPacket(mbuf_t m, void *param)
{
//    XYLog("%s\n", __FUNCTION__);
    IOReturn ret = kIOReturnOutputSuccess;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;

    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || ifp->if_snd.queue == NULL) {
        if (m && mbuf_type(m) != MBUF_TYPE_FREE)
            freePacket(m);
        return kIOReturnOutputDropped;
    }
    if (m == NULL) {
        XYLog("%s m==NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        ret = kIOReturnOutputDropped;
    }
    if (!(mbuf_flags(m) & MBUF_PKTHDR) ){
        XYLog("%s pkthdr is NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        freePacket(m);
        ret = kIOReturnOutputDropped;
    }
    if (mbuf_type(m) == MBUF_TYPE_FREE) {
        XYLog("%s mbuf is FREE!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        ret = kIOReturnOutputDropped;
    }
    size_t len = mbuf_len(m);
    ether_header_t *eh = (ether_header_t *)mbuf_data(m);
    if (len >= sizeof(ether_header_t) && eh->ether_type == htons(ETHERTYPE_PAE)) { // EAPOL packet
        const char* dump = hexdump((uint8_t*)mbuf_data(m), len);
        XYLog("output EAPOL packet, len: %zu, data: %s\n", len, dump ? dump : "Failed to allocate memory");
        if (dump)
            IOFree((void*)dump, 3 * len + 1);
    }
    if (!ifp->if_snd.queue->lockEnqueue(m)) {
        freePacket(m);
        ret = kIOReturnOutputDropped;
    }
    (*ifp->if_start)(ifp);
    return ret;
}
#endif

const OSString * AirportRTW::newVendorString() const
{
    return OSString::withCString("Apple");
}

const OSString * AirportRTW::newModelString() const
{
    return OSString::withCString(fHalService->getDriverInfo()->getFirmwareName());
}

IOReturn AirportRTW::getHardwareAddress(IOEthernetAddress *addrP)
{
    if (IEEE80211_ADDR_EQ(etheranyaddr, fHalService->get80211Controller()->ic_myaddr))
        return kIOReturnError;
    else {
        IEEE80211_ADDR_COPY(addrP, fHalService->get80211Controller()->ic_myaddr);
        return kIOReturnSuccess;
    }
}

IOReturn AirportRTW::setHardwareAddress(const void *addrP, UInt32 addrBytes)
{
    if (!fNetIf || !addrP || !bsdInterface || !bsdInterface->getIfnet())
        return kIOReturnNotReady;
    const UInt8 *address = static_cast<const UInt8 *>(addrP);
    auto ic = fHalService->get80211Controller();
    bool initializing = (ic->ic_if.if_flags & IFF_UP) && !(ic->ic_if.if_flags & IFF_RUNNING);
    auto update = AirportWCL::planMacUpdate(ic->ic_myaddr, address, addrBytes, initializing);
    if (update == AirportWCL::MacUpdate::Invalid)
        return kIOReturnBadArgument;
    if (update == AirportWCL::MacUpdate::Busy)
        return kIOReturnBusy;

    UInt8 previous[ETHER_ADDR_LEN];
    memcpy(previous, ic->ic_myaddr, sizeof(previous));
    if (ifnet_set_lladdr(bsdInterface->getIfnet(), address, addrBytes))
        return kIOReturnError;
    bsdInterface->setProperty(kIOMACAddress, const_cast<UInt8 *>(address), addrBytes);
    if (update == AirportWCL::MacUpdate::Unchanged)
        return kIOReturnSuccess;

    bool running = (ic->ic_if.if_flags & IFF_RUNNING) != 0;
    if_setlladdr(&ic->ic_if, address);
    // if_setlladdr updates arpcom's Ethernet address, not ic_myaddr.
    // MLME and HAL enable() must use the same private address as data TX.
    memcpy(ic->ic_myaddr, address, ETHER_ADDR_LEN);
    if (!running)
        return kIOReturnSuccess; // enable() programs the new vif address.

    ic->ic_wcl_mac_reconfig = true;
    IOReturn status = fHalService->disable(bsdInterface);
    if (status == kIOReturnSuccess)
        status = fHalService->enable(bsdInterface);
    if (status == kIOReturnSuccess)
        return status;

    // Never report a successful address change if firmware failed to start.
    if_setlladdr(&ic->ic_if, previous);
    memcpy(ic->ic_myaddr, previous, ETHER_ADDR_LEN);
    ifnet_set_lladdr(bsdInterface->getIfnet(), previous, sizeof(previous));
    bsdInterface->setProperty(kIOMACAddress, previous, sizeof(previous));
    ic->ic_wcl_mac_reconfig = false;
    if (!(ic->ic_if.if_flags & IFF_RUNNING))
        fHalService->enable(bsdInterface); // Best-effort recovery at the old address.
    return status;
}

UInt32 AirportRTW::getFeatures() const
{
    return fHalService->getDriverInfo()->supportedFeatures();
}

IOReturn AirportRTW::setPromiscuousMode(IOEnetPromiscuousMode mode)
{
    return kIOReturnSuccess;
}

IOReturn AirportRTW::setMulticastMode(IOEnetMulticastMode mode)
{
    return kIOReturnSuccess;
}

IOReturn AirportRTW::setMulticastList(IOEthernetAddress* addr, UInt32 len)
{
    return fHalService->getDriverController()->setMulticastList(addr, len);
}

IOReturn AirportRTW::getPacketFilters(const OSSymbol *group, UInt32 *filters) const
{
    IOReturn    rtn = kIOReturnSuccess;
    if (group == gIOEthernetWakeOnLANFilterGroup && magicPacketSupported)
        *filters = kIOEthernetWakeOnMagicPacket;
    else if (group == gIONetworkFilterGroup)
        *filters = kIOPacketFilterMulticast | kIOPacketFilterPromiscuous;
    else
        rtn = IOEthernetController::getPacketFilters(group, filters);
    return rtn;
}

SInt32 AirportRTW::
enableFeature(IO80211FeatureCode code, void *data)
{
    if (code == kIO80211Feature80211n) {
        return 0;
    }
    return 102;
}

bool AirportRTW::getLogPipes(CCPipe**logPipe, CCPipe**eventPipe, CCPipe**snapshotsPipe)
{
    bool ret = false;
    if (logPipe) {
        *logPipe = driverLogPipe;
        ret = true;
    }
    if (eventPipe) {
        *eventPipe = driverDataPathPipe;
        ret = true;
    }
    if (snapshotsPipe) {
        *snapshotsPipe = driverSnapshotsPipe;
        ret = true;
    }
    return ret;
}

#define APPLE80211_CAPA_AWDL_FEATURE_AUTO_UNLOCK    0x00000004
#define APPLE80211_CAPA_AWDL_FEATURE_WOW            0x00000080

IOReturn AirportRTW::
getCARD_CAPABILITIES(OSObject *object,
                                     struct apple80211_capability_data *cd)
{
    uint32_t caps = fHalService->get80211Controller()->ic_caps;
    memset(cd, 0, sizeof(struct apple80211_capability_data));

    if (caps & IEEE80211_C_WEP)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_WEP;
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_TKIP | 1 << APPLE80211_CAP_AES_CCM;
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_PMGT)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_PMGT;
    // if (caps & IEEE80211_C_IBSS)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_IBSS;
    // if (caps & IEEE80211_C_HOSTAP)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_HOSTAP;
    // AES not enabled, like on Apple cards

    if (caps & IEEE80211_C_SHSLOT)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHSLOT - 8);
    if (caps & IEEE80211_C_SHPREAMBLE)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHPREAMBLE - 8);
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_WPA1 - 8) | 1 << (APPLE80211_CAP_WPA2 - 8) | 1 << (APPLE80211_CAP_TKIPMIC - 8);
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_TXPMGT)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_TXPMGT - 8);
    // if (caps & IEEE80211_C_MONITOR)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_MONITOR - 8);
    // WPA not enabled, like on Apple cards

    cd->version = APPLE80211_VERSION;
#ifdef AIRPORT_WCL
    // WPA2 can use TKIP for group traffic even when unicast uses CCMP.
    // net80211 handles TKIP/MIC in software; hiding it makes Apple80211
    // reject these networks before it submits an association request.
    cd->capabilities[0] = (caps & IEEE80211_C_RSN) ?
        (1 << APPLE80211_CAP_AES_CCM) | (1 << APPLE80211_CAP_TKIP) : 0;
    cd->capabilities[1] &= ~(1 << (APPLE80211_CAP_WPA1 - 8));
    cd->capabilities[5] = 0x40; // Scan completion events.
    if (caps & IEEE80211_C_MFP) {
        cd->capabilities[6] |= 0x01; // PMF
        cd->capabilities[9] |= 0x18; // SAE authentication and key management
    }
    cd->capabilities[2] = (1 << (APPLE80211_CAP_WME - 16)) |
        (1 << (APPLE80211_CAP_SHORT_GI_40MHZ - 16)) |
        (1 << (APPLE80211_CAP_SHORT_GI_20MHZ - 16));
    // Tahoe WCLDeviceConfiguration::isHeSupported reads byte 17, bit 7.
    // WCL uses this capability together with the BSS HE IE for PHY reporting.
    const auto *ic = fHalService->get80211Controller();
    if (ic->ic_hecaps && (ic->ic_flags & IEEE80211_F_HEON))
        cd->capabilities[17] |= 0x80;
#else
    cd->capabilities[2] = 0xFF; // BURST, WME, SHORT_GI_40MHZ, SHORT_GI_20MHZ, WOW, TSN, ?, ?
    cd->capabilities[3] = 0x2B;
    cd->capabilities[5] = 0x40;
    cd->capabilities[6] = (
//                           1 |    //MFP capable
                           0x8 |
                           0x4 |
                           0x80
                           );
    *(uint16_t *)&cd->capabilities[8] = 0x201;
//
//    cd->capabilities[2] |= 0x10;
//    cd->capabilities[5] |= 0x1;
//
//    cd->capabilities[2] |= 0x2;
//
//    cd->capabilities[3] |= 0x20;
//
//    cd->capabilities[0] |= 0x80;
//
//    cd->capabilities[3] |= 0x80;
//    cd->capabilities[4] |= 0x4;
//
//    cd->capabilities[4] |= 0x1;
//    cd->capabilities[3] |= 0x1;
//    cd->capabilities[6] |= 0x8;
//
//    cd->capabilities[3] |= 3;
//    cd->capabilities[4] |= 2;
//    cd->capabilities[6] |= 0x10;
//    cd->capabilities[5] |= 0x20;
//    cd->capabilities[5] |= 0x80;
//
//    if (cd->capabilities[6] & 0x20) {
//        cd->capabilities[2] |= 8;
//    }
//    cd->capabilities[5] |= 8;
//    cd->capabilities[8] |= 2;
//
//    cd->capabilities[11] |= (2 | 4 | 8 | 0x10 | 0x20 | 0x40 | 0x80);

#endif
    return kIOReturnSuccess;
}

IOReturn AirportRTW::
getDRIVER_VERSION(OSObject *object,
                                  struct apple80211_version_data *hv)
{
    if (!hv)
        return kIOReturnError;
    hv->version = APPLE80211_VERSION;
    snprintf(hv->string, sizeof(hv->string), "%s", fHalService->getDriverInfo()->getFirmwareVersion());
    hv->string_len = strlen(hv->string);
    return kIOReturnSuccess;
}

IOReturn AirportRTW::
getHARDWARE_VERSION(OSObject *object,
                                    struct apple80211_version_data *hv)
{
    if (!hv)
        return kIOReturnError;
    hv->version = APPLE80211_VERSION;
    strncpy(hv->string, fHalService->getDriverInfo()->getFirmwareVersion(), sizeof(hv->string));
    hv->string_len = strlen(fHalService->getDriverInfo()->getFirmwareVersion());
    return kIOReturnSuccess;
}

IOReturn AirportRTW::
getCOUNTRY_CODE(OSObject *object,
                                struct apple80211_country_code_data *cd)
{
    if (!cd) return kIOReturnBadArgument;
    memset(cd, 0, sizeof(*cd));
    cd->version = APPLE80211_VERSION;
    const char *cc = fHalService->getDriverInfo()->getFirmwareCountryCode();
    if (cc) memcpy(cd->cc, cc, 2);
    return kIOReturnSuccess;
}

IOReturn AirportRTW::
setCOUNTRY_CODE(OSObject *object, struct apple80211_country_code_data *data)
{
    if (!data) return kIOReturnBadArgument;
    auto *info = fHalService->getDriverInfo();
    const char *cc = info->getFirmwareCountryCode();
    if (cc && memcmp(cc, data->cc, 2) == 0) return kIOReturnSuccess;
    if (!info->setCountryCode(reinterpret_cast<const char *>(data->cc)))
        return kIOReturnUnsupported;
    if (fNetIf)
        static_cast<AirportRTWSkywalkInterface *>(fNetIf)->handleWCLEvent(
            IEEE80211_EVT_COUNTRY_CODE_UPDATE, nullptr);
    return kIOReturnSuccess;
}

IOReturn AirportRTW::
getPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
    if (!pd)
        return kIOReturnError;
    pd->version = APPLE80211_VERSION;
    pd->num_radios = 4;
    pd->power_state[0] = power_state;
    pd->power_state[1] = power_state;
    pd->power_state[2] = power_state;
    pd->power_state[3] = power_state;
    return kIOReturnSuccess;
}

IOReturn AirportRTW::
setPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
#ifdef AIRPORT_WCL
    if (!pd)
        return kIOReturnError;
    RTW_LOG("itlwm: setPOWER: num_radios[%d]  power_state(0:%u  1:%u  2:%u  3:%u)\n", pd->num_radios, pd->power_state[0], pd->power_state[1], pd->power_state[2], pd->power_state[3]);
    if (pd->num_radios > 0) {
        bool isRunning = (fHalService->get80211Controller()->ic_ac.ac_if.if_flags & IFF_RUNNING) != 0;
        if (pd->power_state[0] == 0) {
            fHalService->get80211Controller()->ic_wcl_mac_reconfig = false;
            changePowerStateToPriv(kPowerStateOff);
            if (fHalService->get80211Controller()->ic_ac.ac_if.if_flags & (IFF_UP | IFF_RUNNING)) {
                net80211_ifstats(fHalService->get80211Controller());
                disableAdapter(bsdInterface);
            }
        } else {
            changePowerStateToPriv(kPowerStateOn);
            if (!isRunning)
                enableAdapter(bsdInterface);
        }
        power_state = (pd->power_state[0]);
    }

    return kIOReturnSuccess;
#else
    if (!pd)
        return kIOReturnError;
    RTW_LOG("itlwm: setPOWER: num_radios[%d]  power_state(0:%u  1:%u  2:%u  3:%u)\n", pd->num_radios, pd->power_state[0], pd->power_state[1], pd->power_state[2], pd->power_state[3]);
    if (pd->num_radios > 0) {
        bool isRunning = (fHalService->get80211Controller()->ic_ac.ac_if.if_flags & (IFF_UP | IFF_RUNNING)) != 0;
        if (pd->power_state[0] == 0) {
            changePowerStateToPriv(1);
            if (isRunning) {
                net80211_ifstats(fHalService->get80211Controller());
                disableAdapter(bsdInterface);
            }
        } else {
            changePowerStateToPriv(2);
            if (!isRunning)
                enableAdapter(bsdInterface);
        }
        power_state = (pd->power_state[0]);
    }

    return kIOReturnSuccess;
#endif
}

SInt32 AirportRTW::apple80211_ioctl(IO80211SkywalkInterface *interface,unsigned long cmd,void *data, bool b1, bool b2)
{
    if (!ml_at_interrupt_context())
        XYLog("%s cmd: %s b1: %d b2: %d\n", __FUNCTION__, convertApple80211IOCTLToString((unsigned int)cmd), b1, b2);
#ifdef AIRPORT_WCL
    return kIOReturnUnsupported;
#else
    return super::apple80211_ioctl(interface, cmd, data, b1, b2);
#endif
}

SInt32 AirportRTW::apple80211SkywalkRequest(UInt request,int cmd,IO80211SkywalkInterface *interface,void *data)
{
    if (!ml_at_interrupt_context())
        XYLog("%s 1 cmd: %s request: %d\n", __FUNCTION__, convertApple80211IOCTLToString(cmd), request);
    return kIOReturnUnsupported;
}

SInt32 AirportRTW::apple80211SkywalkRequest(UInt request,int cmd,IO80211SkywalkInterface *interface,void *data,void *)
{
    if (!ml_at_interrupt_context())
        XYLog("%s 2 cmd: %s request: %d\n", __FUNCTION__, convertApple80211IOCTLToString(cmd), request);
    return kIOReturnUnsupported;
}

IOReturn AirportRTW::enableAdapter(IONetworkInterface *netif)
{
#ifdef AIRPORT_WCL
    IOReturn status = fHalService->enable(netif);
    if (status != kIOReturnSuccess)
        return status;
#else
    fHalService->enable(netif);
#endif
    watchdogTimer->setTimeoutMS(kWatchDogTimerPeriod);
    watchdogTimer->enable();
    return kIOReturnSuccess;
}

void AirportRTW::disableAdapter(IONetworkInterface *netif)
{
    watchdogTimer->cancelTimeout();
    watchdogTimer->disable();
    fHalService->disable(netif);
}

IOReturn AirportRTW::
tsleepHandler(OSObject* owner, void* arg0, void* arg1, void* arg2, void* arg3)
{
    AirportRTW* dev = OSDynamicCast(AirportRTW, owner);
    if (dev == 0)
        return kIOReturnError;

    if (arg1 == 0) {
        if (_fCommandGate->commandSleep(arg0, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    } else {
        AbsoluteTime deadline;
        clock_interval_to_deadline((*(int*)arg1), kNanosecondScale, reinterpret_cast<uint64_t*> (&deadline));
        if (_fCommandGate->commandSleep(arg0, deadline, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    }
}

bool AirportRTW::initPCIPowerManagment(IOPCIDevice *provider)
{
    UInt16 reg16;

    reg16 = provider->configRead16(kIOPCIConfigCommand);

    reg16 |= ( kIOPCICommandBusMaster       |
               kIOPCICommandMemorySpace     |
               kIOPCICommandMemWrInvalidate );

    reg16 &= ~kIOPCICommandIOSpace;  // disable I/O space

    provider->configWrite16( kIOPCIConfigCommand, reg16 );
    provider->findPCICapability(kIOPCIPowerManagementCapability,
                                &pmPCICapPtr);
    if (pmPCICapPtr) {
        UInt16 pciPMCReg = provider->configRead32( pmPCICapPtr ) >> 16;
        if (pciPMCReg & kPCIPMCPMESupportFromD3Cold)
            magicPacketSupported = true;
        provider->configWrite16((pmPCICapPtr + 4), 0x8000 );
        IOSleep(10);
    }
    return true;
}

static IOPMPowerState powerStateArray[kPowerStateCount] =
{
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMDeviceUsable, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};

void AirportRTW::unregistPM()
{
    if (powerOffThreadCall) {
        thread_call_free(powerOffThreadCall);
        powerOffThreadCall = NULL;
    }
    if (powerOnThreadCall) {
        thread_call_free(powerOnThreadCall);
        powerOnThreadCall = NULL;
    }
}

IOReturn AirportRTW::setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker)
{
    IOReturn result = IOPMAckImplied;

    if (pmPowerState == powerStateOrdinal)
        return result;
    switch (powerStateOrdinal) {
        case kPowerStateOff:
            if (powerOffThreadCall) {
                retain();
                if (thread_call_enter(powerOffThreadCall))
                    release();
                result = 5000000;
            }
            break;
        case kPowerStateOn:
            if (powerOnThreadCall) {
                retain();
                if (thread_call_enter(powerOnThreadCall))
                    release();
                result = 5000000;
            }
            break;

        default:
            break;
    }
    return result;
}

IOReturn AirportRTW::setWakeOnMagicPacket(bool active)
{
    magicPacketEnabled = active;
    return kIOReturnSuccess;
}

static void handleSetPowerStateOff(thread_call_param_t param0,
                             thread_call_param_t param1)
{
    AirportRTW *self = (AirportRTW *)param0;

    if (param1 == 0)
    {
        self->getCommandGate()->runAction((IOCommandGate::Action)
                                           handleSetPowerStateOff,
                                           (void *) 1);
    }
    else
    {
        self->setPowerStateOff();
        self->release();
    }
}

static void handleSetPowerStateOn(thread_call_param_t param0,
                            thread_call_param_t param1)
{
    AirportRTW *self = (AirportRTW *) param0;

    if (param1 == 0)
    {
        self->getCommandGate()->runAction((IOCommandGate::Action)
                                           handleSetPowerStateOn,
                                           (void *) 1);
    }
    else
    {
        self->setPowerStateOn();
        self->release();
    }
}

IOReturn AirportRTW::registerWithPolicyMaker(IOService *policyMaker)
{
    IOReturn ret;

    pmPowerState = kPowerStateOn;
    pmPolicyMaker = policyMaker;

    powerOffThreadCall = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOff,
                                            (thread_call_param_t)this);
    powerOnThreadCall  = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOn,
                                              (thread_call_param_t)this);
    ret = pmPolicyMaker->registerPowerDriver(this,
                                             powerStateArray,
                                             kPowerStateCount);
    return ret;
}

void AirportRTW::setPowerStateOff()
{
    XYLog("%s\n", __FUNCTION__);
    pmPowerState = kPowerStateOff;
    disableAdapter(bsdInterface);
    pmPolicyMaker->acknowledgeSetPowerState();
}

void AirportRTW::setPowerStateOn()
{
    XYLog("%s\n", __FUNCTION__);
    pmPowerState = kPowerStateOn;
    pmPolicyMaker->acknowledgeSetPowerState();
}
