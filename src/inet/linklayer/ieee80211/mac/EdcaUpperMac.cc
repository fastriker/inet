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

#include "EdcaUpperMac.h"
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
#include "inet/common/INETUtils.h"
#include "inet/common/queue/IPassiveQueue.h"
#include "inet/common/ModuleAccess.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "inet/physicallayer/ieee80211/mode/Ieee80211ModeSet.h"

namespace inet {
namespace ieee80211 {

Define_Module(EdcaUpperMac);

inline std::string suffix(const char *s, int i) {std::stringstream ss; ss << s << i; return ss.str();}

EdcaUpperMac::EdcaUpperMac()
{
}

EdcaUpperMac::~EdcaUpperMac()
{
    delete duplicateDetection;
    delete fragmenter;
    delete reassembly;
    delete utils;
    delete [] contention;

    int numACs = params->isEdcaEnabled() ? 4 : 1;
    for (int i = 0; i < numACs; i++) {
        delete acData[i].frameExchange;
        delete txRetryHandler[i];
    }
    delete params;
    delete[] acData;
    delete[] txRetryHandler;
}

void EdcaUpperMac::initialize()
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

    int numACs = params->isEdcaEnabled() ? 4 : 1;
    acData = new AccessCategoryData[numACs];
    CompareFunc compareFunc = par("prioritizeMulticast") ? (CompareFunc)MacUtils::cmpMgmtOverMulticastOverUnicast : (CompareFunc)MacUtils::cmpMgmtOverData;
    for (int i = 0; i < numACs; i++) {
        acData[i].transmissionQueue.setName(suffix("txQueue-", i).c_str());
        acData[i].transmissionQueue.setup(compareFunc);
    }

    statistics = check_and_cast<IStatistics*>(getModuleByPath(par("statisticsModule")));
    statistics->setMacUtils(utils);
    statistics->setRateControl(rateControl);

    duplicateDetection = new QoSDuplicateDetector();
    fragmenter = check_and_cast<IFragmenter *>(inet::utils::createOne(par("fragmenterClass")));
    reassembly = check_and_cast<IReassembly *>(inet::utils::createOne(par("reassemblyClass")));

    txRetryHandler = new UpperMacTxRetryHandler*[numACs];
    for (int i = 0; i < numACs; i++) {
        txRetryHandler[i] = new UpperMacTxRetryHandler(params, AccessCategory(i));
    }

    WATCH(maxQueueSize);
    WATCH(fragmentationThreshold);
}

inline double fallback(double a, double b) {return a!=-1 ? a : b;}
inline simtime_t fallback(simtime_t a, simtime_t b) {return a!=-1 ? a : b;}

IMacParameters *EdcaUpperMac::extractParameters(const IIeee80211Mode *slowestMandatoryMode)
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

void EdcaUpperMac::handleMessage(cMessage *msg)
{
    if (msg->getContextPointer() != nullptr)
        ((MacPlugin *)msg->getContextPointer())->handleSelfMessage(msg);
    else
        ASSERT(false);
    cleanupFrameExchanges();
}

void EdcaUpperMac::upperFrameReceived(Ieee80211DataOrMgmtFrame *frame)
{
    Enter_Method("upperFrameReceived(\"%s\")", frame->getName());
    take(frame);

    AccessCategory ac = classifyFrame(frame);

    EV_INFO << "Frame " << frame << " received from higher layer, receiver = " << frame->getReceiverAddress() << endl;

    if (maxQueueSize > 0 && acData[ac].transmissionQueue.length() >= maxQueueSize && dynamic_cast<Ieee80211DataFrame *>(frame)) {
        EV << "Dataframe " << frame << " received from higher layer, but its MAC subqueue is full, dropping\n";
        delete frame;
        return;
    }

    ASSERT(!frame->getReceiverAddress().isUnspecified());
    frame->setTransmitterAddress(params->getAddress());
    enqueue(frame, ac);
    if (!contention[ac]->isContentionInProgress())
        startContention(ac);

    cleanupFrameExchanges();
}

void EdcaUpperMac::enqueue(Ieee80211DataOrMgmtFrame *frame, AccessCategory ac)
{
    acData[ac].transmissionQueue.insert(frame);
}

Ieee80211DataOrMgmtFrame* EdcaUpperMac::aggregateIfPossible(AccessCategory ac)
{
    return msduAggregator ?
        check_and_cast<Ieee80211DataOrMgmtFrame *>(msduAggregator->createAggregateFrame(&acData[ac].transmissionQueue)) :
        check_and_cast<Ieee80211DataOrMgmtFrame *>(acData[ac].transmissionQueue.pop());
}

bool EdcaUpperMac::fragmentIfPossible(Ieee80211DataOrMgmtFrame* nextFrame, bool aMsduPresent, AccessCategory ac)
{
    if (nextFrame->getByteLength() > fragmentationThreshold && !aMsduPresent)
    {
        EV_INFO << "The frame length is " << nextFrame->getByteLength() << " octets. Fragmentation threshold is reached. Fragmenting..." << std::endl;
        auto fragments = fragmenter->fragment(nextFrame, fragmentationThreshold);
        EV_INFO << "The fragmentation process finished with " << fragments.size() << "fragments." << std::endl;
        if (acData[ac].transmissionQueue.isEmpty())
        {
            for (Ieee80211DataOrMgmtFrame *fragment : fragments)
                acData[ac].transmissionQueue.insert(fragment);
        }
        else
        {
            cObject *where = acData[ac].transmissionQueue.front();
            for (Ieee80211DataOrMgmtFrame *fragment : fragments)
                acData[ac].transmissionQueue.insertBefore(where, fragment);
        }
        return true;
    }
    return false;
}


void EdcaUpperMac::assignSequenceNumber(Ieee80211DataOrMgmtFrame* frame)
{
    duplicateDetection->assignSequenceNumber(frame);
}

Ieee80211DataOrMgmtFrame* EdcaUpperMac::dequeue(AccessCategory ac)
{
    Enter_Method("dequeue()");
    Ieee80211DataOrMgmtFrame *nextFrame = aggregateIfPossible(ac);
    EV_INFO << nextFrame << " is selected from the transmission queue." << std::endl;
    assignSequenceNumber(nextFrame);
    Ieee80211DataFrame *nextDataFrame = dynamic_cast<Ieee80211DataFrame *>(nextFrame);
    bool aMsduPresent = nextDataFrame && nextDataFrame->getAMsduPresent();
    if (aMsduPresent)
        EV_INFO << "It is an " <<  nextFrame->getByteLength() << " octets long A-MSDU aggregated frame." << std::endl;
    return fragmentIfPossible(nextFrame, aMsduPresent, ac) ? (Ieee80211DataOrMgmtFrame*) acData[ac].transmissionQueue.pop() : nextFrame;
}


AccessCategory EdcaUpperMac::classifyFrame(Ieee80211DataOrMgmtFrame *frame)
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

AccessCategory EdcaUpperMac::mapTidToAc(int tid)
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

void EdcaUpperMac::lowerFrameReceived(Ieee80211Frame *frame)
{
    Enter_Method("lowerFrameReceived(\"%s\")", frame->getName());
    delete frame->removeControlInfo();
    take(frame);

    if (!utils->isForUs(frame)) {
        EV_INFO << "This frame is not for us" << std::endl;
        delete frame;
        corruptedOrNotForUsFrameReceived();
    }
    else if (processOrDeleteLowerFrame(frame)) {
        if (Ieee80211RTSFrame *rtsFrame = dynamic_cast<Ieee80211RTSFrame *>(frame)) {
            sendCts(rtsFrame);
            delete rtsFrame;
        }
        else if (Ieee80211DataOrMgmtFrame *dataOrMgmtFrame = dynamic_cast<Ieee80211DataOrMgmtFrame *>(frame)) {
            if (!utils->isBroadcastOrMulticast(frame))
                sendAck(dataOrMgmtFrame);
            if (duplicateDetection->isDuplicate(dataOrMgmtFrame)) {
                EV_INFO << "Duplicate frame " << frame->getName() << ", dropping\n";
                delete dataOrMgmtFrame;
            }
            else {
                // FIXME: replace with QoS data frame
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
            }
        }
        else {
            EV_INFO << "Unexpected frame " << frame->getName() << ", dropping\n";
            delete frame;
        }
    }
    cleanupFrameExchanges();
}

void EdcaUpperMac::corruptedOrNotForUsFrameReceived()
{
    int numACs = params->isEdcaEnabled() ? 4 : 1;
    for (int i = 0; i < numACs; i++)
        if (acData[i].frameExchange)
            acData[i].frameExchange->corruptedOrNotForUsFrameReceived();
}

void EdcaUpperMac::explodeAggregatedFrame(Ieee80211DataFrame* dataFrame)
{
    EV_INFO << "MSDU aggregated frame received. Exploding it...\n";
    auto frames = msduAggregator->explodeAggregateFrame(dataFrame);
    EV_INFO << "It contained the following subframes:\n";
    for (Ieee80211DataFrame *frame : frames)
    {
        EV_INFO << frame << "\n";
        mac->sendUp(frame);
    }
}

bool EdcaUpperMac::processOrDeleteLowerFrame(Ieee80211Frame *frame)
{
    // show frame to ALL ongoing frame exchanges
    int numACs = params->isEdcaEnabled() ? 4 : 1;
    bool alreadyProcessed = false;
    bool shouldDelete = false;
    for (int i = 0; i < numACs; i++) {
        if (acData[i].frameExchange) {
            IFrameExchange::FrameProcessingResult result = acData[i].frameExchange->lowerFrameReceived(frame);
            bool justProcessed = (result != IFrameExchange::IGNORED);
            ASSERT(!alreadyProcessed || !justProcessed); // ensure it's not double-processed
            if (justProcessed) {
                alreadyProcessed = true;
                shouldDelete = (result == IFrameExchange::PROCESSED_DISCARD);
            }
        }
    }
    if (alreadyProcessed) {
        // jolly good, nothing more to do
        if (shouldDelete)
            delete frame;
        return false;
    }
    return true;
}

void EdcaUpperMac::channelAccessGranted(int txIndex)
{
    EV_INFO << "Channel access granted\n";
    Enter_Method("channelAccessGranted()");
    if (acData[txIndex].frameExchange)
        acData[txIndex].frameExchange->continueFrameExchange();
    else
        startSendDataFrameExchange(dequeue((AccessCategory)txIndex), txIndex, (AccessCategory)txIndex);
}

void EdcaUpperMac::internalCollision(int txIndex)
{
    EV_INFO << "Internal collision occurred\n";
    Enter_Method("internalCollision()");
    if (acData[txIndex].frameExchange) {
        Ieee80211Frame *dataFrame = acData[txIndex].frameExchange->getDataFrame();
        Ieee80211Frame *firstFrame = acData[txIndex].frameExchange->getDataFrame();
        txRetryHandler[txIndex]->frameTransmissionFailed(dataFrame, firstFrame); // Note: failedFrame = firstFrame
        if (txRetryHandler[txIndex]->isRetryPossible(dataFrame, firstFrame))
            startContention((AccessCategory)txIndex);
        else
            acData[txIndex].frameExchange->abortFrameExchange();
    }
    else {
        Ieee80211DataOrMgmtFrame *dataFrame = (Ieee80211DataOrMgmtFrame *)acData[txIndex].transmissionQueue.front();
        txRetryHandler[txIndex]->frameTransmissionFailed(dataFrame, dataFrame); // increments retry counters
        if (txRetryHandler[txIndex]->isRetryPossible(dataFrame, dataFrame))
            startContention((AccessCategory)txIndex);
        else {
            // delete first frame from queue assuming a SendDataFrameWithAckFrameExchange would have been used
            acData[txIndex].transmissionQueue.pop();
        }
    }
}

void EdcaUpperMac::startContention(AccessCategory ac)
{
    EV_INFO << "Starting the contention\n";
    contention[ac]->startContention(params->getAifsTime(ac), params->getEifsTime(ac), params->getCwMulticast(ac), params->getCwMulticast(ac), params->getSlotTime(), 0, this);
}

void EdcaUpperMac::frameTransmissionFailed(IFrameExchange* what, Ieee80211Frame *dataFrame, Ieee80211Frame *failedFrame, AccessCategory ac)
{
    EV_INFO << "Frame transmission failed\n";
    contention[ac]->channelReleased();
    txRetryHandler[ac]->frameTransmissionFailed(dataFrame, failedFrame); // increments retry counters
    if (txRetryHandler[ac]->isRetryPossible(dataFrame, failedFrame))
        startContention(ac);
    else
        what->abortFrameExchange();
}

void EdcaUpperMac::frameTransmissionSucceeded(IFrameExchange* what, Ieee80211Frame* frame, AccessCategory ac)
{
    EV_INFO << "Frame transmission succeeded\n";
    // TODO: statistic, log
    txRetryHandler[ac]->frameTransmissionSucceeded(frame);
}

void EdcaUpperMac::cleanupFrameExchanges()
{
    int numACs = params->isEdcaEnabled() ? 4 : 1;
    for (int i = 0; i < numACs; i++)
    {
        if (acData[i].finished)
        {
            delete acData[i].frameExchange;
            acData[i].frameExchange = nullptr;
            acData[i].finished = false;
        }
    }
}

void EdcaUpperMac::transmissionComplete(ITxCallback *callback)
{
    Enter_Method("transmissionComplete()");
    if (callback)
        callback->transmissionComplete();
}

void EdcaUpperMac::startSendDataFrameExchange(Ieee80211DataOrMgmtFrame *frame, int txIndex, AccessCategory ac)
{
    ASSERT(!acData[ac].frameExchange);

    if (utils->isBroadcastOrMulticast(frame))
        utils->setFrameMode(frame, rateSelection->getModeForMulticastDataOrMgmtFrame(frame));
    else
        utils->setFrameMode(frame, rateSelection->getModeForUnicastDataOrMgmtFrame(frame));

    FrameExchangeContext context;
    context.ownerModule = this;
    context.params = params;
    context.utils = utils;
    context.tx = tx;
    context.rx = rx;
    context.statistics = statistics;

    IFrameExchange *frameExchange;
    bool useRtsCts = frame->getByteLength() > params->getRtsThreshold();
    if (utils->isBroadcastOrMulticast(frame))
        frameExchange = new SendMulticastDataFrameExchange(&context, this, frame, txIndex, ac);
    else if (useRtsCts)
        frameExchange = new SendDataWithRtsCtsFrameExchange(&context, this, frame, txIndex, ac);
    else
        frameExchange = new SendDataWithAckFrameExchange(&context, this, frame, txIndex, ac);

    frameExchange->startFrameExchange();
    if (acData[ac].frameExchange)
        throw cRuntimeError("Frame exchange for AC %d must be a nullptr", ac);
    acData[ac].frameExchange = frameExchange;
}

void EdcaUpperMac::frameExchangeFinished(IFrameExchange *what, bool successful)
{
    EV_INFO << "Frame exchange finished" << std::endl;
    AccessCategory ac = what->getAc();
    ASSERT(ac != -1);
    acData[ac].finished = true;
    contention[ac]->channelReleased();

    if (!acData[ac].transmissionQueue.empty())
        startContention(ac);
}

void EdcaUpperMac::sendAck(Ieee80211DataOrMgmtFrame *frame)
{
    Ieee80211ACKFrame *ackFrame = utils->buildAckFrame(frame);
    tx->transmitFrame(ackFrame, params->getSifsTime(), nullptr);
}

void EdcaUpperMac::sendCts(Ieee80211RTSFrame *frame)
{
    Ieee80211CTSFrame *ctsFrame = utils->buildCtsFrame(frame);
    tx->transmitFrame(ctsFrame, params->getSifsTime(), nullptr);
}

} // namespace ieee80211
} // namespace inet

