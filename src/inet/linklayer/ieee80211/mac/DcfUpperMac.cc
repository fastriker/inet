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

#include "DcfUpperMac.h"
#include "Contention.h"
#include "MacUtils.h"

namespace inet {
namespace ieee80211 {

void DcfUpperMac::initialize()
{
    UpperMacBase::initialize();
    maxQueueSize = par("maxQueueSize");
    IContention **contentions = nullptr;
    collectContentionModules(getModuleByPath(par("firstContentionModule")), contentions);
    CompareFunc compareFunc = par("prioritizeMulticast") ? (CompareFunc)MacUtils::cmpMgmtOverMulticastOverUnicast : (CompareFunc)MacUtils::cmpMgmtOverData;
    foo.transmissionQueue.setName("txQueue");
    foo.transmissionQueue.setup(compareFunc);
    foo.contention = contentions[0];
    foo.txRetryHandler = new UpperMacTxRetryHandler(params, AC_LEGACY);
    foo.ac = AccessCategory(AC_LEGACY);
    WATCH(maxQueueSize);
    WATCH(fragmentationThreshold);
}

void DcfUpperMac::handleMessage(cMessage* msg)
{
    if (static_cast<FrameExchangePlugin*>(msg->getContextPointer())) {
        FrameExchangeState state = ((FrameExchangePlugin *)msg->getContextPointer())->handleSelfMessage(msg);
        if (state.result == FrameExchangeState::TIMEOUT)
            frameTransmissionFailed(foo, state.dataOrMgmtFrame, state.transmittedFrame);
    }
    else
        throw cRuntimeError("Unknown MacPlugin type");
}

void DcfUpperMac::corruptedOrNotForUsFrameReceived()
{
    if (foo.frameExchange)
        foo.frameExchange->corruptedOrNotForUsFrameReceived();
}

bool DcfUpperMac::processLowerFrameIfPossible(Ieee80211Frame* frame)
{
    if (foo.frameExchange == nullptr)
        return false;
    // offer frame to ongoing frame exchange
    FrameExchangeState state = foo.frameExchange->lowerFrameReceived(frame);
    if (state.result == FrameExchangeState::IGNORED)
        return true;
    else if (state.result == FrameExchangeState::ACCEPTED) {
        frameTransmissionSucceeded(foo, state.transmittedFrame);
        delete frame; // already processed, nothing more to do
    }
    else if (state.result == FrameExchangeState::FINISHED) {
        frameTransmissionSucceeded(foo, state.transmittedFrame);
        frameExchangeFinished(foo);
        delete frame; // already processed, nothing more to do
    }
    else
        throw cRuntimeError("Unknown result");
    return false;
}

void DcfUpperMac::upperFrameReceived(Ieee80211DataOrMgmtFrame* frame)
{
    Enter_Method("upperFrameReceived(\"%s\")", frame->getName());
    take(frame);
    EV_INFO << "Frame " << frame << " received from higher layer, receiver = " << frame->getReceiverAddress() << endl;
    if (maxQueueSize > 0 && foo.transmissionQueue.length() >= maxQueueSize && dynamic_cast<Ieee80211DataFrame *>(frame)) {
        EV << "Dataframe " << frame << " received from higher layer but MAC queue is full, dropping\n";
        delete frame;
        return;
    }
    ASSERT(!frame->getReceiverAddress().isUnspecified());
    frame->setTransmitterAddress(params->getAddress());
    foo.transmissionQueue.insert(frame);
    startContentionIfNecessary(foo);
}

void DcfUpperMac::lowerFrameReceived(Ieee80211Frame* frame)
{
    UpperMacBase::lowerFrameReceived(frame);
}

void DcfUpperMac::transmissionComplete()
{
    // TODO: dubious, why isn't it in the frame exchange
    if (dynamic_cast<SendMulticastDataFrameExchange *>(foo.frameExchange))
        frameExchangeFinished(foo); // We are not waiting for response.
    else
        foo.frameExchange->continueFrameExchange();
}

void DcfUpperMac::internalCollision(int txIndex)
{
    throw cRuntimeError("Internal collision is impossible in DCF mode");
}

void DcfUpperMac::channelAccessGranted(int txIndex)
{
    if (foo.frameExchange)
        foo.frameExchange->continueFrameExchange();
    else
        startFrameExchange(foo, txIndex); // TODO: txIndex?
}

} /* namespace ieee80211 */
} /* namespace inet */

