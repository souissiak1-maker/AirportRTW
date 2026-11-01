/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef RTW_AWDL_WINDOW_SCHEDULER_HPP
#define RTW_AWDL_WINDOW_SCHEDULER_HPP
#include "RTWAwdlElection.hpp"
namespace RTWAwdl {
struct ScheduledWindow {
    uint64_t startUs {0},endUs {0},actualStartUs {0};
    uint16_t counter {0};
    uint8_t channel {0},presence {0},role {0};
    uint8_t parent[6] {},root[6] {};
};
// Integration hooks run on one native workloop. Radio calls are synchronous;
// no hardware lock may remain held while delivering a native event. A false
// event result means no handoff, not a negative peer-manager acknowledgment.
class WindowDriver {
public:
    enum class Reservation { Granted, Rejected, RecoveryRequired };
    virtual ~WindowDriver()=default;
    virtual uint64_t nowUs() const=0;
    virtual bool ready() const=0;
    virtual bool channelAllowed(uint8_t) const=0;
    virtual uint8_t currentChannel() const=0;
    virtual Reservation reserve(uint8_t channel,uint32_t durationMs)=0;
    virtual bool restore()=0;
    virtual bool wireTime(uint64_t hostUs,uint32_t &wireUs) const=0;
    virtual bool armTimer(uint64_t deadlineUs,uint64_t nowUs)=0;
    virtual void cancelTimer()=0;
    virtual bool windowStart(const ScheduledWindow &,uint32_t wireUs)=0;
    virtual bool windowEnd(const ScheduledWindow &,uint32_t wireUs)=0;
};
class WindowScheduler {
public:
    enum class Phase : uint8_t { Stopped,Idle,Preparing,Reserved,Opening,Open,Closing,Returning,Failed };
    // Driver and engine must outlive this scheduler and its serialized callbacks.
    WindowScheduler(Election::State &state,WindowDriver &driver):state_(state),driver_(driver) {}
    ~WindowScheduler() {stop();}
    // Maximum visit includes preparation, avoiding a fictitious full window
    // after a slow switch. Longer presence modes need a different radio profile.
    bool start(uint32_t maximumVisitUs,uint32_t preparationLeadUs=0) {
        if (phase_!=Phase::Stopped || state_.controlsHeld || !driver_.ready() || !maximumVisitUs || maximumVisitUs>100000 ||
            preparationLeadUs>=maximumVisitUs || !Election::validSequence(state_.sequence) ||
            !Election::validPresence(state_.presence) || state_.sequence.step+1!=state_.presence ||
            !Election::unicast(state_.mac) || !Election::unicast(state_.master) ||
            uint32_t(state_.presence)*Election::awUs>maximumVisitUs-preparationLeadUs)
            return false;
        uint32_t wire;
        if(!driver_.wireTime(driver_.nowUs(),wire))return false;
        maximumVisit_=maximumVisitUs;lead_=preparationLeadUs;
        sampleCount_=sampleNext_=0;
        if(lead_) {samples_[0]=lead_;sampleCount_=sampleNext_=1;}
        stopRequested_=false;phase_=Phase::Idle;
        if(!armAfter(driver_.nowUs(),1)) {phase_=Phase::Stopped;return false;}
        return true;
    }
    bool stop() {
        stopRequested_=true;driver_.cancelTimer();
        if (phase_==Phase::Preparing || phase_==Phase::Opening || phase_==Phase::Closing)
            return false; // The in-progress dispatch finishes cancellation.
        if (phase_==Phase::Stopped) return true;
        if (phase_==Phase::Open) closeWindow(driver_.nowUs());
        return returnHome();
    }
    void service() {
        if (phase_==Phase::Stopped || phase_==Phase::Failed || phase_==Phase::Preparing ||
            phase_==Phase::Opening || phase_==Phase::Closing || phase_==Phase::Returning) return;
        uint64_t now=driver_.nowUs();
        if (stopRequested_ || !driver_.ready()) { stop();return; }
        if (phase_==Phase::Open) {
            uint32_t wire;
            if (now<window_.endUs && now>=window_.actualStartUs && driver_.wireTime(now,wire) &&
                driver_.currentChannel()==window_.channel && driver_.channelAllowed(window_.channel) &&
                driver_.nowUs()<window_.endUs) {
                if(!arm(window_.endUs))stop();
                return;
            }
            closeWindow(now);
            if(!returnHome() || phase_==Phase::Stopped)return;
            now=driver_.nowUs();
        }
        if (phase_==Phase::Reserved) {
            ScheduledWindow current;
            const uint64_t coordinate=now<window_.startUs ? window_.startUs : now;
            if (!currentWindow(state_,coordinate,current) || !same(current,window_) ||
                !driver_.channelAllowed(window_.channel) || driver_.currentChannel()!=window_.channel ||
                now>window_.startUs+lateToleranceUs) {
                returnHome();return;
            }
            if (now<window_.startUs) {if(!arm(window_.startUs))stop();return;}
            openWindow(now);return;
        }
        if (phase_!=Phase::Idle)return;
        uint32_t wire;
        if(!driver_.wireTime(now,wire)) {if(!armAfter(now,5000))stop();return;}
        state_.elect(now);
        ScheduledWindow planned;
        if(!plan(now,planned)) {if(!armAfter(now,5000))stop();return;}
        const uint64_t requestAt=planned.startUs>lead_ ? planned.startUs-lead_ : 0;
        if(now<requestAt) {if(!arm(requestAt))stop();return;}
        if(planned.endUs<=now || planned.endUs-now>maximumVisit_) {
            skip_=planned;haveSkip_=true;if(!armAfter(now,1000))stop();return;
        }
        window_=planned;skip_=planned;haveSkip_=true;
        // Arm the expiry before entering a synchronous, possibly slow driver.
        if(!arm(window_.endUs)) {stop();return;}
        phase_=Phase::Preparing;
        const auto result=driver_.reserve(window_.channel,uint32_t((window_.endUs-now+999)/1000));
        const uint64_t completed=driver_.nowUs();
        const uint64_t cost=completed>=now ? completed-now : maximumVisit_;
        observeCost(cost);
        if(result==WindowDriver::Reservation::Rejected) {
            driver_.cancelTimer();phase_=Phase::Idle;
            if(stopRequested_)phase_=Phase::Stopped;
            else if(!armAfter(completed,1000))stop();
            return;
        }
        leaseOwned_=true;phase_=Phase::Reserved;
        if(result!=WindowDriver::Reservation::Granted || stopRequested_ || completed<now ||
            completed>=window_.endUs || completed>window_.startUs+lateToleranceUs ||
            driver_.currentChannel()!=window_.channel) {
            returnHome();return;
        }
        if(completed<window_.startUs) {if(!arm(window_.startUs))stop();return;}
        openWindow(completed);
    }
    // Explicit retry after a failed restore. No new visit is granted while
    // recovery owns the radio; teardown must handle an unrecoverable device.
    bool recover() { return phase_==Phase::Failed && !nativeResetRequired_ && returnHome(); }
    bool nativeResetRequired() const {return nativeResetRequired_;}
    bool canTransmit(uint64_t now,bool multicast=false) const {
        if(phase_!=Phase::Open || stopRequested_ || now<window_.actualStartUs ||
           now-window_.actualStartUs<guardUs || now>=window_.endUs ||
           window_.endUs-now<=guardUs || driver_.currentChannel()!=window_.channel ||
           !driver_.ready() || !driver_.channelAllowed(window_.channel))return false;
        // Driver queries may wait for hardware serialization. Recheck actual
        // time afterward rather than authorizing TX with a stale caller clock.
        const uint64_t observed=driver_.nowUs();
        if(observed<now || observed<window_.actualStartUs ||
           observed-window_.actualStartUs<guardUs || observed>=window_.endUs ||
           window_.endUs-observed<=guardUs)return false;
        uint32_t wire;
        if(!driver_.wireTime(observed,wire))return false;
        const unsigned slot=(window_.counter/window_.presence)%Election::slots;
        return !multicast || slot==0 || slot==10;
    }
    Phase phase() const {return phase_;}
    const ScheduledWindow &window() const {return window_;}
    static bool currentWindow(const Election::State &state,uint64_t now,ScheduledWindow &out) {
        out={};
        if(!state.radioScheduleReady() || !Election::validSequence(state.sequence) ||
           !Election::validPresence(state.presence) || now<state.epoch)return false;
        const uint32_t period=uint32_t(state.presence)*Election::awUs;
        const uint32_t remaining=state.untilNext(now);
        if(!remaining || remaining>period || now<period-remaining || now>UINT64_MAX-remaining)return false;
        out.startUs=now-(period-remaining);out.endUs=now+remaining;
        const uint16_t counter=state.counter(now);
        out.counter=uint16_t(counter-counter%state.presence);
        out.channel=state.channel(now);out.presence=state.presence;
        return true;
    }
private:
    static constexpr uint32_t lateToleranceUs=5*1024,guardUs=2*1024;
    static bool same(const ScheduledWindow &a,const ScheduledWindow &b) {
        return a.startUs==b.startUs && a.endUs==b.endUs && a.counter==b.counter && a.channel==b.channel;
    }
    bool plan(uint64_t now,ScheduledWindow &out) const {
        if(now>UINT64_MAX-lead_)return false;
        uint64_t probe=now+lead_;
        for(unsigned i=0;i<=Election::slots;++i) {
            ScheduledWindow w;
            if(!currentWindow(state_,probe,w))return false;
            if(w.channel && driver_.channelAllowed(w.channel) &&
               probe-w.startUs<=lateToleranceUs && (!haveSkip_ || !same(w,skip_))) {out=w;return true;}
            if(w.endUs<=probe)return false;
            probe=w.endUs;
        }
        return false;
    }
    void observeCost(uint64_t cost) {
        samples_[sampleNext_++%8]=uint32_t(cost>maximumVisit_ ? maximumVisit_ : cost);
        if(sampleCount_<8)++sampleCount_;
        uint32_t highest=0;
        for(unsigned i=0;i<sampleCount_;++i)if(samples_[i]>highest)highest=samples_[i];
        const uint32_t period=uint32_t(state_.presence)*Election::awUs;
        const uint32_t budget=period<maximumVisit_ ? maximumVisit_-period : 0;
        lead_=highest>=budget || budget-highest<1000 ? budget : highest+1000;
    }
    bool arm(uint64_t deadline) {return driver_.armTimer(deadline,driver_.nowUs());}
    bool armAfter(uint64_t now,uint32_t delay) {
        return now<=UINT64_MAX-delay && arm(now+delay);
    }
    void openWindow(uint64_t now) {
        if(now>=window_.endUs || !driver_.ready() || !driver_.channelAllowed(window_.channel)) {
            returnHome();return;
        }
        // Channel/policy queries can block. A delayed return must not produce
        // a start stamped with the earlier pre-query time.
        now=driver_.nowUs();
        if(now<window_.startUs || now>window_.startUs+lateToleranceUs || now>=window_.endUs) {
            returnHome();return;
        }
        uint32_t wire;
        if(!driver_.wireTime(now,wire)) {returnHome();return;}
        window_.actualStartUs=now;
        window_.role=state_.syncRole==3 ? 3 : (state_.synchronized || state_.nativeClockHoldover ? 2 : 1);
        for(unsigned i=0;i<6;++i){window_.parent[i]=state_.sync[i];window_.root[i]=state_.master[i];}
        state_.holdControls();state_.holdClock(window_.endUs);phase_=Phase::Opening;
        const bool handedOff=driver_.windowStart(window_,wire);
        if(handedOff)state_.nativeTimelineStarted=true;
        phase_=handedOff ? Phase::Open : Phase::Reserved;
        if(!handedOff){state_.holdClock(0);state_.releaseControls(driver_.nowUs());}
        if(!handedOff || stopRequested_) {if(handedOff)closeWindow(driver_.nowUs());returnHome();return;}
        if(!arm(window_.endUs))stop();
    }
    void closeWindow(uint64_t now) {
        if(phase_!=Phase::Open)return;
        phase_=Phase::Closing;
        const uint64_t end=now<window_.endUs ? now : window_.endUs;
        uint32_t wire;
        if(now<window_.actualStartUs || !driver_.wireTime(end,wire) || !driver_.windowEnd(window_,wire))
            nativeResetRequired_=true;
        state_.holdClock(0);
        if(stopRequested_ || nativeResetRequired_)state_.discardControls();
        else state_.releaseControls(driver_.nowUs());
        phase_=Phase::Reserved;
    }
    bool returnHome() {
        driver_.cancelTimer();phase_=Phase::Returning;
        if(leaseOwned_ && !driver_.restore()) {phase_=Phase::Failed;return false;}
        leaseOwned_=false;
        if(nativeResetRequired_) {phase_=Phase::Failed;return false;}
        phase_=stopRequested_ ? Phase::Stopped : Phase::Idle;
        if(phase_==Phase::Idle && !armAfter(driver_.nowUs(),1000)) {
            stopRequested_=true;phase_=Phase::Stopped;return false;
        }
        return true;
    }
    Election::State &state_;
    WindowDriver &driver_;
    Phase phase_ {Phase::Stopped};
    ScheduledWindow window_ {},skip_ {};
    uint32_t maximumVisit_ {0},lead_ {0},samples_[8] {};
    unsigned sampleCount_ {0},sampleNext_ {0};
    bool leaseOwned_ {false},stopRequested_ {false},haveSkip_ {false},nativeResetRequired_ {false};
};
}
#endif
