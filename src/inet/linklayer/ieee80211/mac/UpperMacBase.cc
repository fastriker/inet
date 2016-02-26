//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#include "UpperMacBase.h"
#include "Ieee80211Mac.h"
#include "IRx.h"
#include "IContention.h"
#include "ITx.h"
#include "MacUtils.h"
#include "MacParameters.h"
#include "FrameExchanges.h"
#include "DuplicateDetectors.h"
#include "MsduAggregation.h"
#include "IFragmentation.h"
#include "IRateSelection.h"
#include "IRateControl.h"
#include "IStatistics.h"
#include "FrameResponder.h"
#include "inet/common/INETUtils.h"
#include "inet/common/queue/IPassiveQueue.h"
#include "inet/common/ModuleAccess.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211ModeSet.h"

namespace inet {
namespace ieee80211 {

inline double fallback(double a, double b) {return a!=-1 ? a : b;}
inline simtime_t fallback(simtime_t a, simtime_t b) {return a!=-1 ? a : b;}
inline std::string suffix(const char *s, int i) {std::stringstream ss; ss << s << i; return ss.str();}

void UpperMacBase::initialize()
{
    mac = check_and_cast<Ieee80211Mac *>(getModuleByPath(par("macModule")));
    rx = check_and_cast<IRx *>(getModuleByPath(par("rxModule")));
    tx = check_and_cast<ITx *>(getModuleByPath(par("txModule")));
    rateSelection = check_and_cast<IRateSelection*>(getModuleByPath(par("rateSelectionModule")));
    rateControl = dynamic_cast<IRateControl*>(getModuleByPath(par("rateControlModule"))); // optional module
    rateSelection->setRateControl(rateControl);
    params = extractParameters(rateSelection->getSlowestMandatoryMode());
    utils = new MacUtils(params, rateSelection);
    rx->setAddress(params->getAddress());
    statistics = check_and_cast<IStatistics*>(getModuleByPath(par("statisticsModule")));
    statistics->setMacUtils(utils);
    statistics->setRateControl(rateControl);
    duplicateDetection = new QoSDuplicateDetector();
    fragmenter = check_and_cast<IFragmenter *>(inet::utils::createOne(par("fragmenterClass")));
    reassembly = check_and_cast<IReassembly *>(inet::utils::createOne(par("reassemblyClass")));

    WATCH(fragmentationThreshold);
}

IMacParameters *UpperMacBase::extractParameters(const IIeee80211Mode *slowestMandatoryMode)
{
    const IIeee80211Mode *referenceMode = slowestMandatoryMode;  // or any other; slotTime etc must be the same for all modes we use

    MacParameters *params = new MacParameters();
    params->setAddress(mac->getAddress());
    params->setShortRetryLimit(fallback(par("shortRetryLimit"), 7));
    params->setLongRetryLimit(fallback(par("longRetryLimit"), 4));
    params->setRtsThreshold(par("rtsThreshold"));
    params->setPhyRxStartDelay(referenceMode->getPhyRxStartDelay());
    params->setUseFullAckTimeout(par("useFullAckTimeout"));
    params->setEdcaEnabled(true);
    params->setSlotTime(fallback(par("slotTime"), referenceMode->getSlotTime()));
    params->setSifsTime(fallback(par("sifsTime"), referenceMode->getSifsTime()));
    int aCwMin = referenceMode->getLegacyCwMin();
    int aCwMax = referenceMode->getLegacyCwMax();

    for (int i = 0; i < 4; i++) {
        AccessCategory ac = (AccessCategory)i;
        int aifsn = fallback(par(suffix("aifsn",i).c_str()), MacUtils::getAifsNumber(ac));
        params->setAifsTime(ac, params->getSifsTime() + aifsn*params->getSlotTime());
        params->setEifsTime(ac, params->getSifsTime() + params->getAifsTime(ac) + slowestMandatoryMode->getDuration(LENGTH_ACK));
        params->setCwMin(ac, fallback(par(suffix("cwMin",i).c_str()), MacUtils::getCwMin(ac, aCwMin)));
        params->setCwMax(ac, fallback(par(suffix("cwMax",i).c_str()), MacUtils::getCwMax(ac, aCwMax, aCwMin)));
        params->setCwMulticast(ac, fallback(par(suffix("cwMulticast",i).c_str()), MacUtils::getCwMin(ac, aCwMin)));
    }
    return params;
}

void UpperMacBase::startContention(Foo& foo)
{
    EV_INFO << "Starting the contention\n";
    foo.contention->startContention(params->getAifsTime(foo.ac), params->getEifsTime(foo.ac), params->getSlotTime(), foo.txRetryHandler->getCw(), this);
}

void UpperMacBase::startContentionIfNecessary(Foo& foo)
{
    if (!foo.contention->isContentionInProgress())
        startContention(foo);
    else
        EV_INFO << "Contention has already started\n";
}

void UpperMacBase::releaseChannel(IContention* contention)
{
    contention->channelReleased();
}

Ieee80211DataOrMgmtFrame* UpperMacBase::extractNextFrameToTransmit(cQueue *queue)
{
    Enter_Method("dequeue()");
    Ieee80211DataOrMgmtFrame *nextFrame = aggregateIfPossible(queue);
    EV_INFO << nextFrame << " is selected from the transmission queue.\n";
    assignSequenceNumber(nextFrame);
    Ieee80211DataFrame *nextDataFrame = dynamic_cast<Ieee80211DataFrame *>(nextFrame);
    bool aMsduPresent = nextDataFrame && nextDataFrame->getAMsduPresent();
    if (aMsduPresent)
        EV_INFO << "It is an " <<  nextFrame->getByteLength() << " octets long A-MSDU aggregated frame.\n";
    return fragmentIfNecessary(queue, nextFrame, aMsduPresent) ? (Ieee80211DataOrMgmtFrame*) queue->pop() : nextFrame;
}

void UpperMacBase::assignSequenceNumber(Ieee80211DataOrMgmtFrame* frame)
{
    duplicateDetection->assignSequenceNumber(frame);
}

Ieee80211DataOrMgmtFrame* UpperMacBase::aggregateIfPossible(cQueue *queue)
{
    return msduAggregator ?
        check_and_cast<Ieee80211DataOrMgmtFrame *>(msduAggregator->createAggregateFrame(queue)) :
        check_and_cast<Ieee80211DataOrMgmtFrame *>(queue->pop());
}

void UpperMacBase::lowerFrameReceived(Ieee80211Frame* frame)
{
    Enter_Method("lowerFrameReceived(\"%s\")", frame->getName());
    delete frame->removeControlInfo(); // TODO
    take(frame);
    if (!utils->isForUs(frame)) {
        EV_INFO << "This frame is not for us\n";
        delete frame;
        corruptedOrNotForUsFrameReceived();
    }
    else if (processLowerFrameIfPossible(frame)) {
        EV_INFO << "Lower frame can be processed by an ongoing frame exchange.\n";
    }
    else {
        bool responded = frameResponder->respondToLowerFrameIfPossible(frame);
        bool shouldDelete = sendUpIfNecessary(frame);
        if (shouldDelete) {
            if (!responded)
                EV_WARN << "Unexpected frame " << frame->getName() << ", dropping\n";
            delete frame;
        }
    }
}

bool UpperMacBase::sendUpIfNecessary(Ieee80211Frame* frame)
{
    if (Ieee80211DataOrMgmtFrame *dataOrMgmtFrame = dynamic_cast<Ieee80211DataOrMgmtFrame *>(frame)) {
        if (duplicateDetection->isDuplicate(dataOrMgmtFrame)) {
            EV_INFO << "Duplicate frame " << frame->getName() << ", dropping\n";
            return true;
        }
        else {
            Ieee80211DataFrame *dataFrame = dynamic_cast<Ieee80211DataFrame*>(dataOrMgmtFrame);
            if (dataFrame && dataFrame->getAMsduPresent())
                sendUpAggregatedFrame(dataFrame);
            else if (!utils->isFragment(dataOrMgmtFrame))
                mac->sendUp(dataOrMgmtFrame);
            else {
                Ieee80211DataOrMgmtFrame *completeFrame = reassembly->addFragment(dataOrMgmtFrame);
                if (completeFrame)
                    mac->sendUp(completeFrame);
            }
            return false;
        }
    }
    return true;
}

void UpperMacBase::frameTransmissionFailed(Foo& foo, Ieee80211DataOrMgmtFrame *dataOrMgmtFrame, Ieee80211Frame *transmittedFrame)
{
    EV_INFO << "Frame transmission failed\n";
    foo.txRetryHandler->frameTransmissionFailed(dataOrMgmtFrame, transmittedFrame); // increments retry counters
    if (foo.txRetryHandler->isRetryPossible(dataOrMgmtFrame, transmittedFrame)) {
        releaseChannel(foo.contention);
        startContention(foo);
    }
    else {
        foo.frameExchange->abortFrameExchange();
        frameExchangeFinished(foo);
    }
}

void UpperMacBase::frameTransmissionSucceeded(Foo& foo, Ieee80211Frame *transmittedFrame)
{
    EV_INFO << "Frame transmission succeeded\n";
    foo.txRetryHandler->frameTransmissionSucceeded(transmittedFrame); // TODO: jó frame?
}

void UpperMacBase::frameExchangeFinished(Foo& foo)
{
    EV_INFO << "Frame exchange finished\n";
    releaseChannel(foo.contention);
    delete foo.frameExchange;
    foo.frameExchange = nullptr;
    if (foo.transmissionQueue.isEmpty())
        startContention(foo);
}

void UpperMacBase::sendUpAggregatedFrame(Ieee80211DataFrame* dataFrame)
{
    EV_INFO << "MSDU aggregated frame received. Exploding it...\n";
    auto frames = msduAggregator->explodeAggregateFrame(dataFrame);
    EV_INFO << "It contained the following subframes:\n";
    for (Ieee80211DataFrame *frame : frames) {
        EV_INFO << frame << "\n";
        mac->sendUp(frame);
    }
}

bool UpperMacBase::fragmentIfNecessary(cQueue* queue, Ieee80211DataOrMgmtFrame* nextFrame, bool aMsduPresent)
{
    if (nextFrame->getByteLength() > fragmentationThreshold && !aMsduPresent) {
        EV_INFO << "The frame length is " << nextFrame->getByteLength() << " octets. Fragmentation threshold is reached. Fragmenting...\n";
        auto fragments = fragmenter->fragment(nextFrame, fragmentationThreshold);
        EV_INFO << "The fragmentation process finished with " << fragments.size() << "fragments.\n";
        if (queue->isEmpty()) {
            for (Ieee80211DataOrMgmtFrame *fragment : fragments)
                queue->insert(fragment);
        }
        else {
            cObject *where = queue->front();
            for (Ieee80211DataOrMgmtFrame *fragment : fragments)
                queue->insertBefore(where, fragment);
        }
        return true;
    }
    return false;
}

void UpperMacBase::startFrameExchange(Foo& foo, int txIndex)
{
    ASSERT(!foo.frameExchange);
    Ieee80211DataOrMgmtFrame *frame = extractNextFrameToTransmit(&foo.transmissionQueue);
    if (utils->isBroadcastOrMulticast(frame))
        utils->setFrameMode(frame, rateSelection->getModeForMulticastDataOrMgmtFrame(frame));
    else
        utils->setFrameMode(frame, rateSelection->getModeForUnicastDataOrMgmtFrame(frame));

    // TODO
    FrameExchangeContext context;
    context.ownerModule = nullptr;
    context.params = params;
    context.utils = utils;
    context.tx = nullptr;
    context.rx = nullptr;
    context.statistics = nullptr;

    bool useRtsCts = frame->getByteLength() > params->getRtsThreshold();
    if (utils->isBroadcastOrMulticast(frame))
        foo.frameExchange = new SendMulticastDataFrameExchange(&context, frame, txIndex);
    else if (useRtsCts)
        foo.frameExchange = new SendDataWithRtsCtsFrameExchange(&context, frame, txIndex);
    else
        foo.frameExchange = new SendDataWithAckFrameExchange(&context, frame, txIndex);
    foo.frameExchange->startFrameExchange();
}


} /* namespace ieee80211 */
} /* namespace inet */
