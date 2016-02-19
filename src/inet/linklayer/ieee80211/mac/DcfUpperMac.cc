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
#include "IFrameResponder.h"
#include "IFrameExchangeHandler.h"
#include "inet/common/INETUtils.h"
#include "inet/common/queue/IPassiveQueue.h"
#include "inet/common/ModuleAccess.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211ModeSet.h"

namespace inet {
namespace ieee80211 {

Define_Module(DcfUpperMac);

DcfUpperMac::DcfUpperMac()
{
}

DcfUpperMac::~DcfUpperMac()
{
    delete frameExchange;
    delete duplicateDetection;
    delete fragmenter;
    delete reassembly;
    delete txRetryHandler;
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
    transmissionQueue.setName("txQueue");
    // TODO: fingerprint
    //transmissionQueue.setup(par("prioritizeMulticast") ? (CompareFunc)MacUtils::cmpMgmtOverMulticastOverUnicast : (CompareFunc)MacUtils::cmpMgmtOverData);

    rateSelection = check_and_cast<IRateSelection*>(getModuleByPath(par("rateSelectionModule")));
    msduAggregator = dynamic_cast<IMsduAggregation*>(getModuleByPath(par("msduAggregatorModule")));
    rateControl = dynamic_cast<IRateControl*>(getModuleByPath(par("rateControlModule"))); // optional module
    rateSelection->setRateControl(rateControl);

    params = extractParameters(rateSelection->getSlowestMandatoryMode());
    utils = new MacUtils(params, rateSelection);
    rx->setAddress(params->getAddress());

    statistics = check_and_cast<IStatistics*>(getModuleByPath(par("statisticsModule")));
    statistics->setMacUtils(utils);
    statistics->setRateControl(rateControl);

    duplicateDetection = new NonQoSDuplicateDetector(); //TODO or LegacyDuplicateDetector();
    fragmenter = check_and_cast<IFragmenter *>(inet::utils::createOne(par("fragmenterClass")));
    reassembly = check_and_cast<IReassembly *>(inet::utils::createOne(par("reassemblyClass")));
    txRetryHandler = new UpperMacTxRetryHandler(params, AC_LEGACY);

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
    params->setEdcaEnabled(false);
    params->setSlotTime(fallback(par("slotTime"), referenceMode->getSlotTime()));
    params->setSifsTime(fallback(par("sifsTime"), referenceMode->getSifsTime()));
    int aCwMin = referenceMode->getLegacyCwMin();
    int aCwMax = referenceMode->getLegacyCwMax();
    params->setAifsTime(AC_LEGACY, fallback(par("difsTime"), referenceMode->getSifsTime() + MacUtils::getAifsNumber(AC_LEGACY) * params->getSlotTime()));
    params->setEifsTime(AC_LEGACY, params->getSifsTime() + params->getAifsTime(AC_LEGACY) + slowestMandatoryMode->getDuration(LENGTH_ACK));
    params->setCwMin(AC_LEGACY, fallback(par("cwMin"), MacUtils::getCwMin(AC_LEGACY, aCwMin)));
    params->setCwMax(AC_LEGACY, fallback(par("cwMax"), MacUtils::getCwMax(AC_LEGACY, aCwMax, aCwMin)));
    params->setCwMulticast(AC_LEGACY, fallback(par("cwMulticast"), MacUtils::getCwMin(AC_LEGACY, aCwMin)));
    return params;
}

void DcfUpperMac::handleMessage(cMessage *msg)
{
    if (msg->getContextPointer() != nullptr) {
        if (dynamic_cast<FrameExchangePlugin *>(msg->getContextPointer())) {
            frameExchangeHandler->handleMessage(msg);
        }
    }
    else
        ASSERT(false);
}

void DcfUpperMac::internalCollision(int txIndex)
{
    Enter_Method("internalCollision()");
    throw cRuntimeError("Impossible event: internal collision in DcfUpperMac");
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


void DcfUpperMac::startContention()
{
    // TODO: multicast cw??
    EV_INFO << "Starting the contention\n";
    contention[0]->startContention(params->getAifsTime(AC_LEGACY), params->getEifsTime(AC_LEGACY), params->getSlotTime(), txRetryHandler->getCw(), this);
}


void DcfUpperMac::old_startContention(int retryCount)
{
    EV_INFO << "retry count = " << retryCount << endl;
    contention[0]->startContention(params->getAifsTime(AC_LEGACY), params->getEifsTime(AC_LEGACY), params->getCwMin(AC_LEGACY), params->getCwMax(AC_LEGACY), params->getSlotTime(), retryCount, this);
}

void DcfUpperMac::enqueue(Ieee80211DataOrMgmtFrame *frame)
{
    transmissionQueue.insert(frame);
}

Ieee80211DataOrMgmtFrame* DcfUpperMac::getNextFrameToTransmit()
{
    Enter_Method("dequeue()");
    Ieee80211DataOrMgmtFrame *nextFrame = aggregateIfPossible();
    EV_INFO << nextFrame << " is selected from the transmission queue." << std::endl;
    assignSequenceNumber(nextFrame);
    Ieee80211DataFrame *nextDataFrame = dynamic_cast<Ieee80211DataFrame *>(nextFrame);
    bool aMsduPresent = nextDataFrame && nextDataFrame->getAMsduPresent();
    if (aMsduPresent)
        EV_INFO << "It is an " <<  nextFrame->getByteLength() << " octets long A-MSDU aggregated frame." << std::endl;
    return fragmentIfPossible(nextFrame, aMsduPresent) ? (Ieee80211DataOrMgmtFrame*) transmissionQueue.pop() : nextFrame;
}

void DcfUpperMac::upperFrameReceived(Ieee80211DataOrMgmtFrame *frame)
{
    Enter_Method("upperFrameReceived(\"%s\")", frame->getName());
    take(frame);
    EV_INFO << "Frame " << frame << " received from higher layer, receiver = " << frame->getReceiverAddress() << endl;
    if (maxQueueSize > 0 && transmissionQueue.length() >= maxQueueSize && dynamic_cast<Ieee80211DataFrame *>(frame)) {
        EV << "Dataframe " << frame << " received from higher layer but MAC queue is full, dropping\n";
        delete frame;
        return;
    }
    ASSERT(!frame->getReceiverAddress().isUnspecified());
    frame->setTransmitterAddress(params->getAddress());
    enqueue(frame);
    if (!contention[0]->isContentionInProgress()) {
        startContention();
    }
}

void DcfUpperMac::assignSequenceNumber(Ieee80211DataOrMgmtFrame* frame)
{
    duplicateDetection->assignSequenceNumber(frame);
}

Ieee80211DataOrMgmtFrame *DcfUpperMac::aggregateIfPossible()
{
    // Note: In DCF compliant mode there is no MSDU aggregation.
    return msduAggregator ?
            check_and_cast<Ieee80211DataOrMgmtFrame *>(msduAggregator->createAggregateFrame(&transmissionQueue)) :
            check_and_cast<Ieee80211DataOrMgmtFrame *>(transmissionQueue.pop());
}

bool DcfUpperMac::fragmentIfPossible(Ieee80211DataOrMgmtFrame *nextFrame, bool aMsduPresent)
{
    if (nextFrame->getByteLength() > fragmentationThreshold && !aMsduPresent)
    {
        EV_INFO << "The frame length is " << nextFrame->getByteLength() << " octets. Fragmentation threshold is reached. Fragmenting...\n";
        auto fragments = fragmenter->fragment(nextFrame, fragmentationThreshold);
        EV_INFO << "The fragmentation process finished with " << fragments.size() << "fragments. \n";
        if (transmissionQueue.isEmpty()) {
            for (Ieee80211DataOrMgmtFrame *fragment : fragments)
                transmissionQueue.insert(fragment);
        }
        else {
            cObject *where = transmissionQueue.front();
            for (Ieee80211DataOrMgmtFrame *fragment : fragments)
                transmissionQueue.insertBefore(where, fragment);
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

        // finished? failed?
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

void DcfUpperMac::frameTransmissionFailed()
{
    contention[0]->channelReleased();
    startContention();
}

void DcfUpperMac::frameExchangeFinished()
{
    contention[0]->channelReleased();
    if (!transmissionQueue.empty()) {
        startContention();
    }
}


} // namespace ieee80211
} // namespace inet

