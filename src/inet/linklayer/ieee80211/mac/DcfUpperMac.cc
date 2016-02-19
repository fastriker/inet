//
// Copyright (C) 2015 Andras Varga
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
// Author: Andras Varga
//

#include "DcfUpperMac.h"
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
#include "FrameExchangeHandler.h"
#include "FrameResponder.h"
#include "inet/common/INETUtils.h"
#include "inet/common/queue/IPassiveQueue.h"
#include "inet/common/ModuleAccess.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211ModeSet.h"

namespace inet {
namespace ieee80211 {

Define_Module(DcfUpperMac);

inline std::string suffix(const char *s, int i) {std::stringstream ss; ss << s << i; return ss.str();}

DcfUpperMac::DcfUpperMac()
{
}

DcfUpperMac::~DcfUpperMac()
{
    delete duplicateDetection;
    delete fragmenter;
    delete reassembly;
    delete params;
    delete utils;
    delete [] contention;
}

void DcfUpperMac::initialize()
{
    mac = check_and_cast<Ieee80211Mac *>(getModuleByPath(par("macModule")));
    rx = check_and_cast<IRx *>(getModuleByPath(par("rxModule")));
    tx = check_and_cast<ITx *>(getModuleByPath(par("txModule")));
    contention = nullptr;
    collectContentionModules(getModuleByPath(par("firstContentionModule")), contention);

    maxQueueSize = par("maxQueueSize");

    msduAggregator = dynamic_cast<IMsduAggregation*>(getModuleByPath(par("msduAggregatorModule")));
    rateSelection = check_and_cast<IRateSelection*>(getModuleByPath(par("rateSelectionModule")));
    rateControl = dynamic_cast<IRateControl*>(getModuleByPath(par("rateControlModule"))); // optional module
    rateSelection->setRateControl(rateControl);

    params = extractParameters(rateSelection->getSlowestMandatoryMode());
    utils = new MacUtils(params, rateSelection);
    rx->setAddress(params->getAddress());

    CompareFunc compareFunc = par("prioritizeMulticast") ? (CompareFunc)MacUtils::cmpMgmtOverMulticastOverUnicast : (CompareFunc)MacUtils::cmpMgmtOverData;
    int numACs = params->isEdcaEnabled() ? 4 : 1;
    for (int i = 0; i < numACs; i++) {
        transmissionQueue[i].setName(suffix("txQueue-", i).c_str());
        transmissionQueue[i].setup(compareFunc);
    }

    statistics = check_and_cast<IStatistics*>(getModuleByPath(par("statisticsModule")));
    statistics->setMacUtils(utils);
    statistics->setRateControl(rateControl);

    duplicateDetection = new QoSDuplicateDetector();
    fragmenter = check_and_cast<IFragmenter *>(inet::utils::createOne(par("fragmenterClass")));
    reassembly = check_and_cast<IReassembly *>(inet::utils::createOne(par("reassemblyClass")));

    frameExchangeHandler = new FrameExchangeHandler(this, params, utils, rateSelection);
    frameResponder = new FrameResponder(params, utils, tx);

    WATCH(maxQueueSize);
    WATCH(fragmentationThreshold);
}

inline double fallback(double a, double b) {return a!=-1 ? a : b;}
inline simtime_t fallback(simtime_t a, simtime_t b) {return a!=-1 ? a : b;}

IMacParameters *DcfUpperMac::extractParameters(const IIeee80211Mode *slowestMandatoryMode)
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

void DcfUpperMac::handleMessage(cMessage *msg)
{
    if (msg->getContextPointer() != nullptr) {
        if (static_cast<FrameExchangePlugin *>(msg->getContextPointer())) {
            frameExchangeHandler->handleMessage(msg);
        }
    }
    else
        ASSERT(false);
}

void DcfUpperMac::internalCollision(int txIndex) // TODO: int <-> AccessCategory
{
    EV_INFO << "Internal collision occurred\n";
    Enter_Method("internalCollision()");
    frameExchangeHandler->internalCollision(AccessCategory(txIndex));
}

void DcfUpperMac::transmissionComplete()
{
    Enter_Method("transmissionComplete()");
    EV_DETAIL << "Transmission complete\n";
    frameExchangeHandler->transmissionComplete();
}


void DcfUpperMac::channelAccessGranted(int txIndex)
{
    EV_INFO << "Channel access granted\n";
    Enter_Method("channelAccessGranted()");
    frameExchangeHandler->channelAccessGranted(txIndex);
}


void DcfUpperMac::startContention(AccessCategory ac, int cw)
{
    if (!contention[ac]->isContentionInProgress()) {
        EV_INFO << "Starting the contention\n";
        contention[ac]->startContention(params->getAifsTime(ac), params->getEifsTime(ac), params->getCwMulticast(ac), params->getCwMulticast(ac), params->getSlotTime(), cw, this);
    }
    else {
        EV_INFO << "Contention has already started\n";
    }
}

void DcfUpperMac::enqueue(Ieee80211DataOrMgmtFrame *frame, AccessCategory ac)
{
    transmissionQueue[ac].insert(frame);
}

Ieee80211DataOrMgmtFrame* DcfUpperMac::dequeueNextFrameToTransmit(AccessCategory ac)
{
    Enter_Method("dequeue()");
    Ieee80211DataOrMgmtFrame *nextFrame = aggregateIfPossible(ac);
    EV_INFO << nextFrame << " is selected from the transmission queue.\n";
    assignSequenceNumber(nextFrame);
    Ieee80211DataFrame *nextDataFrame = dynamic_cast<Ieee80211DataFrame *>(nextFrame);
    bool aMsduPresent = nextDataFrame && nextDataFrame->getAMsduPresent();
    if (aMsduPresent)
        EV_INFO << "It is an " <<  nextFrame->getByteLength() << " octets long A-MSDU aggregated frame.\n";
    return fragmentIfPossible(nextFrame, aMsduPresent, ac) ? (Ieee80211DataOrMgmtFrame*) transmissionQueue[ac].pop() : nextFrame;
}

void DcfUpperMac::upperFrameReceived(Ieee80211DataOrMgmtFrame *frame)
{
    Enter_Method("upperFrameReceived(\"%s\")", frame->getName());
    take(frame);
    AccessCategory ac = classifyFrame(frame);
    EV_INFO << "Frame " << frame << " received from higher layer, receiver = " << frame->getReceiverAddress() << endl;
    if (maxQueueSize > 0 && transmissionQueue[ac].length() >= maxQueueSize && dynamic_cast<Ieee80211DataFrame *>(frame)) {
        EV << "Dataframe " << frame << " received from higher layer, but its MAC subqueue is full, dropping\n";
        delete frame;
        return;
    }
    ASSERT(!frame->getReceiverAddress().isUnspecified());
    frame->setTransmitterAddress(params->getAddress());
    enqueue(frame, ac);
    frameExchangeHandler->upperFrameReceived(ac);
}

void DcfUpperMac::assignSequenceNumber(Ieee80211DataOrMgmtFrame* frame)
{
    duplicateDetection->assignSequenceNumber(frame);
}

Ieee80211DataOrMgmtFrame* DcfUpperMac::aggregateIfPossible(AccessCategory ac)
{
    return msduAggregator ?
        check_and_cast<Ieee80211DataOrMgmtFrame *>(msduAggregator->createAggregateFrame(&transmissionQueue[ac])) :
        check_and_cast<Ieee80211DataOrMgmtFrame *>(transmissionQueue[ac].pop());
}

bool DcfUpperMac::fragmentIfPossible(Ieee80211DataOrMgmtFrame* nextFrame, bool aMsduPresent, AccessCategory ac)
{
    if (nextFrame->getByteLength() > fragmentationThreshold && !aMsduPresent)
    {
        EV_INFO << "The frame length is " << nextFrame->getByteLength() << " octets. Fragmentation threshold is reached. Fragmenting...\n";
        auto fragments = fragmenter->fragment(nextFrame, fragmentationThreshold);
        EV_INFO << "The fragmentation process finished with " << fragments.size() << "fragments.\n";
        if (transmissionQueue[ac].isEmpty())
        {
            for (Ieee80211DataOrMgmtFrame *fragment : fragments)
                transmissionQueue[ac].insert(fragment);
        }
        else
        {
            cObject *where = transmissionQueue[ac].front();
            for (Ieee80211DataOrMgmtFrame *fragment : fragments)
                transmissionQueue[ac].insertBefore(where, fragment);
        }
        return true;
    }
    return false;
}

void DcfUpperMac::lowerFrameReceived(Ieee80211Frame* frame)
{
    Enter_Method("lowerFrameReceived(\"%s\")", frame->getName());
    delete frame->removeControlInfo(); // TODO
    take(frame);
    if (!utils->isForUs(frame)) {
        EV_INFO << "This frame is not for us\n";
        delete frame;
        frameExchangeHandler->corruptedOrNotForUsFrameReceived();
    }
    else if (frameExchangeHandler->processLowerFrameIfPossible(frame)) {
        EV_INFO << "Lower frame can be processed by an ongoing frame exchange.\n";
    }
    else {
        bool responded = frameResponder->respondToLowerFrameIfPossible(frame);
        bool sendedUp = sendUpIfNecessary(frame);
        if (!sendedUp && !responded) {
            EV_INFO << "Unexpected frame " << frame->getName() << ", dropping\n";
        }
        if (!sendedUp) {
            delete frame;
        }
    }
}

bool DcfUpperMac::sendUpIfNecessary(Ieee80211Frame* frame)
{
    if (Ieee80211DataOrMgmtFrame *dataOrMgmtFrame = dynamic_cast<Ieee80211DataOrMgmtFrame *>(frame)) {
        if (duplicateDetection->isDuplicate(dataOrMgmtFrame)) {
            EV_INFO << "Duplicate frame " << frame->getName() << ", dropping\n";
            return false;
        }
        else {
            Ieee80211DataFrame *dataFrame = dynamic_cast<Ieee80211DataFrame*>(dataOrMgmtFrame);
            if (dataFrame && dataFrame->getAMsduPresent()) {
                explodeAggregatedFrame(dataFrame);
            }
            else if (!utils->isFragment(dataOrMgmtFrame))
                mac->sendUp(dataOrMgmtFrame);
            else {
                Ieee80211DataOrMgmtFrame *completeFrame = reassembly->addFragment(dataOrMgmtFrame);
                if (completeFrame)
                    mac->sendUp(completeFrame);
            }
            return true;
        }
    }
    return false;
}

void DcfUpperMac::explodeAggregatedFrame(Ieee80211DataFrame* dataFrame)
{
    EV_INFO << "MSDU aggregated frame received. Exploding it...\n";
    auto frames = msduAggregator->explodeAggregateFrame(dataFrame);
    EV_INFO << "It contained the following subframes:\n";
    for (Ieee80211DataFrame *frame : frames) {
        EV_INFO << frame << "\n";
        mac->sendUp(frame);
    }
}

AccessCategory DcfUpperMac::classifyFrame(Ieee80211DataOrMgmtFrame *frame)
{
    if (frame->getType() == ST_DATA) {
        return AC_BE;  // non-QoS frames are Best Effort
    }
    else if (frame->getType() == ST_DATA_WITH_QOS) {
        Ieee80211DataFrame *dataFrame = check_and_cast<Ieee80211DataFrame*>(frame);
        return mapTidToAc(dataFrame->getTid());  // QoS frames: map TID to AC
    }
    else {
        return AC_VO; // management frames travel in the Voice category
    }
}

AccessCategory DcfUpperMac::mapTidToAc(int tid)
{
    // standard static mapping (see "UP-to-AC mappings" table in the 802.11 spec.)
    switch (tid) {
        case 1: case 2: return AC_BK;
        case 0: case 3: return AC_BE;
        case 4: case 5: return AC_VI;
        case 6: case 7: return AC_VO;
        default: throw cRuntimeError("No mapping from TID=%d to AccessCategory (must be in the range 0..7)", tid);
    }
}

bool DcfUpperMac::hasMoreFrameToTransmit(AccessCategory ac)
{
    return transmissionQueue[ac].isEmpty();
}

void DcfUpperMac::releaseChannel(AccessCategory ac)
{
    contention[ac]->channelReleased();
}

void DcfUpperMac::corruptedOrNotForUsFrameReceived()
{
    frameExchangeHandler->corruptedOrNotForUsFrameReceived();
}

Ieee80211DataOrMgmtFrame* DcfUpperMac::getFirstFrame(AccessCategory ac)
{
    return (Ieee80211DataOrMgmtFrame*)transmissionQueue[ac].front();
}

void DcfUpperMac::deleteFirstFrame(AccessCategory ac)
{
    transmissionQueue[ac].pop();
}

} // namespace ieee80211
} // namespace inet

