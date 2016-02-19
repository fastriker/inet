//
// Copyright (C) 2015 OpenSim Ltd.
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

#include "FrameExchangeHandler.h"

namespace inet {
namespace ieee80211 {

bool FrameExchangeHandler::processLowerFrameIfPossible(Ieee80211Frame* frame) // TODO: rename
{
    if (frameExchange == nullptr) return true;
    // offer frame to ongoing frame exchange
    FrameExchangeState state = frameExchange->lowerFrameReceived(frame);
    if (state.result == FrameExchangeState::IGNORED) {
        return true;
    }
    if (state.result == FrameExchangeState::ACCEPTED) {
        frameTransmissionSucceeded(state);
        delete frame; // already processed, nothing more to do
    }
    else if (state.result == FrameExchangeState::FINISHED) {
        frameTransmissionSucceeded(state);
        frameExchangeFinished();
        delete frame; // already processed, nothing more to do
    }
    else {
        throw cRuntimeError("Unknown result");
    }
    return false;
}

void FrameExchangeHandler::startFrameExchange(Ieee80211DataOrMgmtFrame *frame, int txIndex, AccessCategory ac)
{
    ASSERT(!frameExchange);

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

    bool useRtsCts = frame->getByteLength() > params->getRtsThreshold();
    if (frameExchange)
        throw cRuntimeError("Frame exchange must be a nullptr");
    if (utils->isBroadcastOrMulticast(frame))
        frameExchange = new SendMulticastDataFrameExchange(&context, frame, txIndex, ac);
    else if (useRtsCts)
        frameExchange = new SendDataWithRtsCtsFrameExchange(&context, frame, txIndex, ac);
    else
        frameExchange = new SendDataWithAckFrameExchange(&context, frame, txIndex, ac);
    frameExchange->startFrameExchange();
}


void FrameExchangeHandler::frameExchangeFinished()
{
    EV_INFO << "Frame exchange finished" << std::endl;
    delete frameExchange;
    frameExchange = nullptr;
    upperMac->frameExchangeFinished();
}

void FrameExchangeHandler::frameTransmissionSucceeded(FrameExchangeState state)
{
    // TODO: statistic, log
    EV_INFO << "Frame transmission succeeded\n";
    txRetryHandler->frameTransmissionSucceeded(frame);
}

void FrameExchangeHandler::channelAccessGranted(int txIndex) {
    if (frameExchange) {
        frameExchange->continueFrameExchange();
    }
    else {
        startFrameExchange(upperMac->getNextFrameToTransmit(), 0, AC_LEGACY);
    }
}

void FrameExchangeHandler::transmissionComplete() {
    if (dynamic_cast<SendMulticastDataFrameExchange *>(frameExchange)) {
        frameExchangeFinished(); // We are not waiting for ACK.
    }
    else {
        frameExchange->continueFrameExchange();
    }
}

void FrameExchangeHandler::corruptedOrNotForUsFrameReceived()
{
    if (frameExchange) {
        frameExchange->corruptedOrNotForUsFrameReceived();
    }
}

void FrameExchangeHandler::frameTransmissionFailed(FrameExchangeState state)
{
    EV_INFO << "Frame transmission failed\n";
    Ieee80211DataOrMgmtFrame *dataOrMgmtFrame = state.dataOrMgmtFrame;
    Ieee80211Frame *transmittedFrame = state.transmittedFrame;
    txRetryHandler->frameTransmissionFailed(dataOrMgmtFrame, transmittedFrame); // increments retry counters
    if (txRetryHandler->isRetryPossible(dataOrMgmtFrame, transmittedFrame)) {
        upperMac->frameTransmissionFailed();
    }
    else {
        frameExchange->abortFrameExchange();
        frameExchangeFinished();
    }
}

void FrameExchangeHandler::handleMessage(cMessage* msg)
{
    if (dynamic_cast<FrameExchangePlugin*>(msg->getContextPointer())) {
        FrameExchangeState state = ((FrameExchangePlugin *)msg->getContextPointer())->handleSelfMessage(msg);
        if (state.result == FrameExchangeState::TIMEOUT)
            frameTransmissionFailed(state);
    }
    else
        throw cRuntimeError("Error");
}

} /* namespace ieee80211 */
} /* namespace inet */
