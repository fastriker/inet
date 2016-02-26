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

#include "EdcaUpperMac.h"
#include "Contention.h"
#include "MacUtils.h"

namespace inet {
namespace ieee80211 {

inline std::string suffix(const char *s, int i) {std::stringstream ss; ss << s << i; return ss.str();}

Define_Module(EdcaUpperMac);

void EdcaUpperMac::initialize()
{
    UpperMacBase::initialize();
    maxQueueSize = par("maxQueueSize");
    foos = new Foo[4];
    IContention **contentions = nullptr;
    collectContentionModules(getModuleByPath(par("firstContentionModule")), contentions);
    CompareFunc compareFunc = par("prioritizeMulticast") ? (CompareFunc)MacUtils::cmpMgmtOverMulticastOverUnicast : (CompareFunc)MacUtils::cmpMgmtOverData;
    for (int i = 0; i < numACs; i++) {
        foos[i].transmissionQueue.setName(suffix("txQueue-", i).c_str());
        foos[i].transmissionQueue.setup(compareFunc);
        foos[i].contention = contentions[i];
        foos[i].txRetryHandler = new UpperMacTxRetryHandler(params, AccessCategory(i));
        foos[i].ac = AccessCategory(i);
    }
    WATCH(maxQueueSize);
    WATCH(fragmentationThreshold);
}

void EdcaUpperMac::handleMessage(cMessage* msg)
{
    if (static_cast<FrameExchangePlugin*>(msg->getContextPointer())) {
        FrameExchangeState state = ((FrameExchangePlugin *)msg->getContextPointer())->handleSelfMessage(msg);
        if (state.result == FrameExchangeState::TIMEOUT) {
            for (int i = 0; i < numACs; i++) {
                if (msg->getContextPointer() == foos[i].frameExchange) {
                    frameTransmissionFailed(foos[i], state.dataOrMgmtFrame, state.transmittedFrame);
                    break;
                }
            }
        }
    }
    else
        throw cRuntimeError("Unknown MacPlugin type");
}

AccessCategory EdcaUpperMac::classifyFrame(Ieee80211DataOrMgmtFrame *frame)
{
    if (frame->getType() == ST_DATA)
        return AC_BE;  // non-QoS frames are Best Effort
    else if (frame->getType() == ST_DATA_WITH_QOS) {
        Ieee80211DataFrame *dataFrame = check_and_cast<Ieee80211DataFrame*>(frame);
        return mapTidToAc(dataFrame->getTid());  // QoS frames: map TID to AC
    }
    else
        return AC_VO; // management frames travel in the Voice category
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

void EdcaUpperMac::corruptedOrNotForUsFrameReceived()
{
    for (int i = 0; i < numACs; i++) {
        if (foos[i].frameExchange)
            foos[i].frameExchange->corruptedOrNotForUsFrameReceived();
    }
}

bool EdcaUpperMac::processLowerFrameIfPossible(Ieee80211Frame* frame)
{
    // show frame to ALL ongoing frame exchanges
    bool alreadyProcessed = false;
    bool shouldDelete = false;
    for (int i = 0; i < numACs; i++) {
        if (foos[i].frameExchange) {
            FrameExchangeState state = foos[i].frameExchange->lowerFrameReceived(frame);
            bool justProcessed = (state.result != FrameExchangeState::IGNORED);
            ASSERT(!alreadyProcessed || !justProcessed); // ensure it's not double-processed
            if (justProcessed) {
                alreadyProcessed = true;
                if (state.result == FrameExchangeState::ACCEPTED) {
                    shouldDelete = true;
                    frameTransmissionSucceeded(foos[i], state.transmittedFrame);
                }
                else if (state.result == FrameExchangeState::FINISHED) {
                    shouldDelete = true;
                    frameTransmissionSucceeded(foos[i], state.transmittedFrame);
                    frameExchangeFinished(foos[i]);
                }
                else
                    throw cRuntimeError("Unknown result");
            }
        }
    }
    if (alreadyProcessed) {
        if (shouldDelete)
            delete frame;
        // jolly good, nothing more to do
        return true;
    }
    return false;
}

void EdcaUpperMac::upperFrameReceived(Ieee80211DataOrMgmtFrame* frame)
{
    Enter_Method("upperFrameReceived(\"%s\")", frame->getName());
    take(frame);
    AccessCategory ac = classifyFrame(frame);
    EV_INFO << "Frame " << frame << " received from higher layer, receiver = " << frame->getReceiverAddress() << endl;
    if (maxQueueSize > 0 && foos[ac].transmissionQueue.length() >= maxQueueSize && dynamic_cast<Ieee80211DataFrame *>(frame)) {
        EV << "Dataframe " << frame << " received from higher layer, but its MAC subqueue is full, dropping\n";
        delete frame;
        return;
    }
    ASSERT(!frame->getReceiverAddress().isUnspecified());
    frame->setTransmitterAddress(params->getAddress());
    foos[ac].transmissionQueue.insert(frame);
    startContentionIfNecessary(foos[ac]);
}

void EdcaUpperMac::transmissionComplete()
{
    // TODO: dubious, why isn't it in the frame exchange
    if (dynamic_cast<SendMulticastDataFrameExchange *>(foos[channelOwner].frameExchange))
        frameExchangeFinished(foos[channelOwner]); // We are not waiting for response.
    else
        foos[channelOwner].frameExchange->continueFrameExchange();
}

void EdcaUpperMac::releaseChannel(IContention *contention)
{
    channelOwner = AccessCategory(-1);
    UpperMacBase::releaseChannel(contention);
}

void EdcaUpperMac::internalCollision(int txIndex)
{
    AccessCategory ac = AccessCategory(txIndex);
    if (foos[ac].frameExchange) {
        Ieee80211Frame *dataOrMgmtFrame = foos[ac].frameExchange->getDataOrMgmtFrame();
        Ieee80211Frame *nextFrameWaitingForTransmission = foos[ac].frameExchange->getNextFrameWaitingForTransmission();
        foos[ac].txRetryHandler->frameTransmissionFailed(dataOrMgmtFrame, nextFrameWaitingForTransmission);
        if (foos[ac].txRetryHandler->isRetryPossible(dataOrMgmtFrame, nextFrameWaitingForTransmission))
            startContention(foos[ac]);
        else {
            foos[ac].frameExchange->abortFrameExchange();
            deleteFrameExchange(foos[ac]);
        }
    }
    else {
        Ieee80211DataOrMgmtFrame *dataFrame = check_and_cast<Ieee80211DataOrMgmtFrame*>(foos[ac].transmissionQueue.front());
        foos[ac].txRetryHandler->frameTransmissionFailed(dataFrame, dataFrame); // increments retry counters
        if (foos[ac].txRetryHandler->isRetryPossible(dataFrame, dataFrame))
            startContention(foos[ac]);
        else
            // delete first frame from queue assuming a SendDataFrameWithAckFrameExchange would have been used
            delete foos[ac].transmissionQueue.pop();
    }
}

void EdcaUpperMac::lowerFrameReceived(Ieee80211Frame* frame)
{
    UpperMacBase::lowerFrameReceived(frame);
}

void EdcaUpperMac::channelAccessGranted(int txIndex)
{
    channelOwner = AccessCategory(txIndex);
    if (foos[channelOwner].frameExchange)
        foos[channelOwner].frameExchange->continueFrameExchange();
    else
        startFrameExchange(foos[channelOwner], txIndex); // TODO: txIndex?
}

void EdcaUpperMac::deleteFrameExchange(Foo& foo)
{
    delete foo.frameExchange;
    foo.frameExchange = nullptr;
}

EdcaUpperMac::~EdcaUpperMac()
{
    delete[] foos;
}

} /* namespace ieee80211 */
} /* namespace inet */

