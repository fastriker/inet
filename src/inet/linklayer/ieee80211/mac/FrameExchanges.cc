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

#include "FrameExchanges.h"
#include "inet/common/INETUtils.h"
#include "inet/common/FSMA.h"
#include "IContention.h"
#include "ITx.h"
#include "IRx.h"
#include "IMacParameters.h"
#include "IStatistics.h"
#include "MacUtils.h"
#include "Ieee80211Frame_m.h"

using namespace inet::utils;

namespace inet {
namespace ieee80211 {

SendDataWithAckFrameExchange::SendDataWithAckFrameExchange(FrameExchangeContext *context, IFrameExchangeCallback *callback, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex, AccessCategory accessCategory) :
    StepBasedFrameExchange(context, callback, txIndex, accessCategory), dataFrame(dataFrame)
{
    dataFrame->setDuration(params->getSifsTime() + utils->getAckDuration());
}

SendDataWithAckFrameExchange::~SendDataWithAckFrameExchange()
{
    delete dataFrame;
}

std::string SendDataWithAckFrameExchange::info() const
{
    std::string ret = StepBasedFrameExchange::info();
    if (dataFrame) {
        ret += ", frame=";
        ret += dataFrame->getName();
    }
    return ret;
}

void SendDataWithAckFrameExchange::doStep(int step)
{
    switch (step) {
        case 0: transmitFrame(dupPacketAndControlInfo(dataFrame)); break;
        case 1:
            if (params->getUseFullAckTimeout())
                expectFullReplyWithin(utils->getAckFullTimeout());
            else
                expectReplyRxStartWithin(utils->getAckEarlyTimeout());
            break;
        case 2: statistics->frameTransmissionSuccessful(dataFrame, retryCount); succeed(); break;
        default: ASSERT(false);
    }
}

IFrameExchange::FrameProcessingResult SendDataWithAckFrameExchange::processReply(int step, Ieee80211Frame *frame)
{
    switch (step) {
        case 1:
            if (utils->isAck(frame)) {
                upperMac->frameTransmissionSucceeded(this, dataFrame, defaultAccessCategory);
                return PROCESSED_DISCARD;
            }
            else
                return IGNORED;
        default: ASSERT(false); return IGNORED;
    }
}

void SendDataWithAckFrameExchange::processTimeout(int step)
{
    switch (step) {
        case 1:
            transmissionFailed();
            break;
        default: ASSERT(false);
    }
}


void SendDataWithAckFrameExchange::transmissionFailed()
{
    dataFrame->setRetry(true);
    gotoStep(0);
    upperMac->frameTransmissionFailed(this, dataFrame, dataFrame, defaultAccessCategory);
}


//------------------------------

SendDataWithRtsCtsFrameExchange::SendDataWithRtsCtsFrameExchange(FrameExchangeContext *context, IFrameExchangeCallback *callback, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex, AccessCategory accessCategory) :
    StepBasedFrameExchange(context, callback, txIndex, accessCategory), dataFrame(dataFrame)
{
    dataFrame->setDuration(params->getSifsTime() + utils->getAckDuration());
    rtsFrame = utils->buildRtsFrame(dataFrame);
}

SendDataWithRtsCtsFrameExchange::~SendDataWithRtsCtsFrameExchange()
{
    delete dataFrame;
    delete rtsFrame;
}

std::string SendDataWithRtsCtsFrameExchange::info() const
{
    std::string ret = StepBasedFrameExchange::info();
    if (dataFrame) {
        ret += ", frame=";
        ret += dataFrame->getName();
    }
    return ret;
}

void SendDataWithRtsCtsFrameExchange::doStep(int step)
{
    switch (step) {
        case 0: transmitFrame(dupPacketAndControlInfo(rtsFrame)); break;
        case 1: expectReplyRxStartWithin(utils->getCtsEarlyTimeout()); break;
        case 2: transmitFrame(dupPacketAndControlInfo(dataFrame), params->getSifsTime()); break;
        case 3: expectReplyRxStartWithin(utils->getAckEarlyTimeout()); break;
        case 4: /*statistics->frameTransmissionSuccessful(dataFrame, longRetryCount);*/ succeed(); break;
        default: ASSERT(false);
    }
}

IFrameExchange::FrameProcessingResult SendDataWithRtsCtsFrameExchange::processReply(int step, Ieee80211Frame *frame)
{
    switch (step) {
        case 1:
            if (utils->isCts(frame)) {
                upperMac->frameTransmissionSucceeded(this, rtsFrame, defaultAccessCategory);
                return PROCESSED_DISCARD;
            }
            else
                return IGNORED;
        case 3:
            if (utils->isAck(frame)) {
                upperMac->frameTransmissionSucceeded(this, dataFrame, defaultAccessCategory);
                return PROCESSED_DISCARD;
            }
            else
                return IGNORED;
        default: ASSERT(false); return IGNORED;
    }
}

void SendDataWithRtsCtsFrameExchange::processTimeout(int step)
{
    switch (step) {
        case 1: transmissionFailed(dataFrame, rtsFrame); break;
        case 3: transmissionFailed(dataFrame, dataFrame); break;
        default: ASSERT(false);
    }
}

void SendDataWithRtsCtsFrameExchange::transmissionFailed(Ieee80211Frame* dataFrame, Ieee80211Frame* failedFrame)
{
    if (failedFrame->getType() == ST_DATA)
        failedFrame->setRetry(true);
    gotoStep(0);
    upperMac->frameTransmissionFailed(this, dataFrame, failedFrame, defaultAccessCategory);
}

//------------------------------

SendMulticastDataFrameExchange::SendMulticastDataFrameExchange(FrameExchangeContext *context, IFrameExchangeCallback *callback, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex, AccessCategory accessCategory) :
    FrameExchange(context, callback), dataFrame(dataFrame), txIndex(txIndex), accessCategory(accessCategory)
{
    ASSERT(utils->isBroadcastOrMulticast(dataFrame));
    dataFrame->setDuration(0);
}

SendMulticastDataFrameExchange::~SendMulticastDataFrameExchange()
{
    delete dataFrame;
}

std::string SendMulticastDataFrameExchange::info() const
{
    return dataFrame ? std::string("frame=") + dataFrame->getName() : "";
}

void SendMulticastDataFrameExchange::handleSelfMessage(cMessage *msg)
{
    ASSERT(false);
}

void SendMulticastDataFrameExchange::startFrameExchange()
{
    tx->transmitFrame(dupPacketAndControlInfo(dataFrame), SIMTIME_ZERO, this);
}

void SendMulticastDataFrameExchange::continueFrameExchange()
{
}

void SendMulticastDataFrameExchange::abortFrameExchange()
{
    reportFailure();
}

void SendMulticastDataFrameExchange::transmissionComplete()
{
    reportSuccess();
}

} // namespace ieee80211
} // namespace inet

