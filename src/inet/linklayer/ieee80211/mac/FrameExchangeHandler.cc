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
#include "FrameExchanges.h"

namespace inet {
namespace ieee80211 {

bool FrameExchangeHandler::processLowerFrameIfPossible(Ieee80211Frame *frame)
{
    // show frame to ALL ongoing frame exchanges
    int numACs = params->isEdcaEnabled() ? 4 : 1;
    bool alreadyProcessed = false;
    bool shouldDelete = false;
    for (int i = 0; i < numACs; i++) {
        if (frameExchanges[i]) {
            FrameExchangeState state = frameExchanges[i]->lowerFrameReceived(frame);
            bool justProcessed = (state.result != FrameExchangeState::IGNORED);
            ASSERT(!alreadyProcessed || !justProcessed); // ensure it's not double-processed
            if (justProcessed) {
                alreadyProcessed = true;
                if (state.result == FrameExchangeState::ACCEPTED) {
                    shouldDelete = true;
                    frameTransmissionSucceeded(state);
                }
                else if (state.result == FrameExchangeState::FINISHED) {
                    shouldDelete = true;
                    frameTransmissionSucceeded(state);
                    frameExchangeFinished(state);
                }
                else
                    throw cRuntimeError("Unknown result");
            }
        }
    }
    if (alreadyProcessed) {
        // jolly good, nothing more to do
        if (shouldDelete)
            delete frame;
        return true;
    }
    return false;
}

void FrameExchangeHandler::startFrameExchange(Ieee80211DataOrMgmtFrame *frame, int txIndex, AccessCategory ac)
{
    // TODO: txIndexet kiirtani, ugyanaz, mint az ac.
    ASSERT(!frameExchanges[ac]);

    if (utils->isBroadcastOrMulticast(frame))
        utils->setFrameMode(frame, rateSelection->getModeForMulticastDataOrMgmtFrame(frame));
    else
        utils->setFrameMode(frame, rateSelection->getModeForUnicastDataOrMgmtFrame(frame));

    // TODO::::::::::::::::::::::::::::::
    FrameExchangeContext context;
    context.ownerModule = nullptr;
    context.params = params;
    context.utils = utils;
    context.tx = nullptr;
    context.rx = nullptr;
    context.statistics = nullptr;

    bool useRtsCts = frame->getByteLength() > params->getRtsThreshold();
    if (utils->isBroadcastOrMulticast(frame))
        frameExchanges[ac] = new SendMulticastDataFrameExchange(&context, frame, txIndex, ac);
    else if (useRtsCts)
        frameExchanges[ac] = new SendDataWithRtsCtsFrameExchange(&context, frame, txIndex, ac);
    else
        frameExchanges[ac] = new SendDataWithAckFrameExchange(&context, frame, txIndex, ac);
    frameExchanges[ac]->startFrameExchange();
}


void FrameExchangeHandler::frameExchangeFinished(FrameExchangeState state)
{
    frameExchangeFinished(state.ac);
}

void FrameExchangeHandler::frameExchangeFinished(AccessCategory ac)
{
    EV_INFO << "Frame exchange finished\n";
    delete frameExchanges[ac];
    frameExchanges[ac] = nullptr;
    upperMac->releaseChannel(ac);
    channelOwner = AccessCategory(-1);
    if (upperMac->hasMoreFrameToTransmit(ac))
        upperMac->startContention(ac, txRetryHandlers[ac]->getCw());
}

void FrameExchangeHandler::frameTransmissionSucceeded(FrameExchangeState state)
{
    EV_INFO << "Frame transmission succeeded\n";
    AccessCategory ac = state.ac;
    txRetryHandlers[ac]->frameTransmissionSucceeded(state.transmittedFrame); // TODO: jó frame?
}

void FrameExchangeHandler::channelAccessGranted(int txIndex) {
    channelOwner = AccessCategory(txIndex);
    if (frameExchanges[channelOwner]) {
        frameExchanges[channelOwner]->continueFrameExchange();
    }
    else {
        startFrameExchange(upperMac->dequeueNextFrameToTransmit(channelOwner), 0, channelOwner); // TODO txIndex
    }
}

void FrameExchangeHandler::transmissionComplete() {
    if (dynamic_cast<SendMulticastDataFrameExchange *>(frameExchanges[channelOwner])) {
        frameExchangeFinished(channelOwner); // We are not waiting for response.
    }
    else {
        frameExchanges[channelOwner]->continueFrameExchange();
    }
}

void FrameExchangeHandler::corruptedOrNotForUsFrameReceived()
{
    int numACs = params->isEdcaEnabled() ? 4 : 1;
    for (int i = 0; i < numACs; i++) {
        if (frameExchanges[i])
            frameExchanges[i]->corruptedOrNotForUsFrameReceived();
    }
}

void FrameExchangeHandler::frameTransmissionFailed(FrameExchangeState state)
{
    EV_INFO << "Frame transmission failed\n";
    AccessCategory ac = state.ac;
    Ieee80211DataOrMgmtFrame *dataOrMgmtFrame = state.dataOrMgmtFrame;
    Ieee80211Frame *transmittedFrame = state.transmittedFrame;
    txRetryHandlers[ac]->frameTransmissionFailed(dataOrMgmtFrame, transmittedFrame); // increments retry counters
    if (txRetryHandlers[ac]->isRetryPossible(dataOrMgmtFrame, transmittedFrame)) {
        upperMac->releaseChannel(ac);
        channelOwner = AccessCategory(-1);
        upperMac->startContention(ac, txRetryHandlers[ac]->getCw());
    }
    else {
        frameExchanges[ac]->abortFrameExchange();
        frameExchangeFinished(ac);
    }
}

void FrameExchangeHandler::handleMessage(cMessage* msg)
{
    if (static_cast<FrameExchangePlugin*>(msg->getContextPointer())) {
        FrameExchangeState state = ((FrameExchangePlugin *)msg->getContextPointer())->handleSelfMessage(msg);
        if (state.result == FrameExchangeState::TIMEOUT)
            frameTransmissionFailed(state);
    }
    else
        throw cRuntimeError("Unknown MacPlugin type");
}

FrameExchangeHandler::FrameExchangeHandler(IUpperMac* upperMac, IMacParameters *params, MacUtils *utils, IRateSelection *rateSelection)
{
    this->utils = utils;
    this->upperMac = upperMac;
    this->rateSelection = rateSelection;
    int numACs = params->isEdcaEnabled() ? 4 : 1;
    txRetryHandlers = new UpperMacTxRetryHandler*[numACs];
    frameExchanges = new IFrameExchange*[numACs];
    for (int i = 0; i < numACs; i++) {
        txRetryHandlers[i] = new UpperMacTxRetryHandler(params, AccessCategory(i));
    }
}

void FrameExchangeHandler::internalCollision(AccessCategory ac)
{
    if (frameExchanges[ac]) {
        Ieee80211Frame *dataOrMgmtFrame = frameExchanges[ac]->getDataOrMgmtFrame();
        Ieee80211Frame *nextFrameWaitingForTransmission = frameExchanges[ac]->getNextFrameWaitingForTransmission();
        txRetryHandlers[ac]->frameTransmissionFailed(dataOrMgmtFrame, nextFrameWaitingForTransmission);
        if (txRetryHandlers[ac]->isRetryPossible(dataOrMgmtFrame, nextFrameWaitingForTransmission)) {
            upperMac->startContention(ac, txRetryHandlers[ac]->getCw());
        }
        else
            frameExchanges[ac]->abortFrameExchange();
    }
    else {
        Ieee80211DataOrMgmtFrame *dataFrame = upperMac->getFirstFrame(ac);
        txRetryHandlers[ac]->frameTransmissionFailed(dataFrame, dataFrame); // increments retry counters
        if (txRetryHandlers[ac]->isRetryPossible(dataFrame, dataFrame)) {
            upperMac->startContention(ac, txRetryHandlers[ac]->getCw());
        }
        else {
            // delete first frame from queue assuming a SendDataFrameWithAckFrameExchange would have been used
            upperMac->deleteFirstFrame(ac);
        }
    }
}

void FrameExchangeHandler::upperFrameReceived(AccessCategory ac)
{
    upperMac->startContention(ac, txRetryHandlers[ac]->getCw());
}

FrameExchangeHandler::~FrameExchangeHandler()
{
    int numACs = params->isEdcaEnabled() ? 4 : 1;
    for (int i = 0; i < numACs; i++) {
        delete txRetryHandlers[i];
    }
    delete[] txRetryHandlers;
    delete[] frameExchanges;
}

} /* namespace ieee80211 */
} /* namespace inet */

