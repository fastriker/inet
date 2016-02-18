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

SendDataWithAckFrameExchange::SendDataWithAckFrameExchange(FrameExchangeContext *context, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex, AccessCategory accessCategory) :
    StepBasedFrameExchange(context, txIndex, accessCategory), dataOrMgmtFrame(dataFrame)
{
    dataFrame->setDuration(params->getSifsTime() + utils->getAckDuration());
}

SendDataWithAckFrameExchange::~SendDataWithAckFrameExchange()
{
    delete dataOrMgmtFrame;
}

std::string SendDataWithAckFrameExchange::info() const
{
    std::string ret = StepBasedFrameExchange::info();
    if (dataOrMgmtFrame) {
        ret += ", frame=";
        ret += dataOrMgmtFrame->getName();
    }
    return ret;
}

void SendDataWithAckFrameExchange::doStep(int step)
{
    switch (step) {
        case 0: transmitFrame(dupPacketAndControlInfo(dataOrMgmtFrame)); break;
        case 1:
            if (params->getUseFullAckTimeout())
                expectFullReplyWithin(utils->getAckFullTimeout());
            else
                expectReplyRxStartWithin(utils->getAckEarlyTimeout());
            break;
        case 2: /*statistics->frameTransmissionSuccessful(dataOrMgmtFrame, retryCount);*/ succeed(); break;
        default: ASSERT(false);
    }
}

FrameExchangeState SendDataWithAckFrameExchange::processReply(int step, Ieee80211Frame *frame)
{
    switch (step) {
        case 1:
            if (utils->isAck(frame)) {
                return FrameExchangeState(FrameExchangeState::ACCEPTED, defaultAccessCategory, dataOrMgmtFrame, dataOrMgmtFrame);
            }
            else
                return FrameExchangeState(FrameExchangeState::IGNORED, defaultAccessCategory, dataOrMgmtFrame, dataOrMgmtFrame);
        default: ASSERT(false);
        return FrameExchangeState::DONT_CARE;
    }
}

FrameExchangeState SendDataWithAckFrameExchange::processTimeout(int step)
{
    switch (step) {
        case 1: return transmissionFailed();
        default: ASSERT(false);
    }
}


FrameExchangeState SendDataWithAckFrameExchange::transmissionFailed()
{
    dataOrMgmtFrame->setRetry(true);
    gotoStep(0);
    return FrameExchangeState(FrameExchangeState::TIMEOUT, defaultAccessCategory, dataOrMgmtFrame, dataOrMgmtFrame);
}


//------------------------------

SendDataWithRtsCtsFrameExchange::SendDataWithRtsCtsFrameExchange(FrameExchangeContext *context, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex, AccessCategory accessCategory) :
    StepBasedFrameExchange(context, txIndex, accessCategory), dataOrMgmtFrame(dataFrame)
{
    dataFrame->setDuration(params->getSifsTime() + utils->getAckDuration());
    rtsFrame = utils->buildRtsFrame(dataFrame);
}

SendDataWithRtsCtsFrameExchange::~SendDataWithRtsCtsFrameExchange()
{
    delete dataOrMgmtFrame;
    delete rtsFrame;
}

std::string SendDataWithRtsCtsFrameExchange::info() const
{
    std::string ret = StepBasedFrameExchange::info();
    if (dataOrMgmtFrame) {
        ret += ", frame=";
        ret += dataOrMgmtFrame->getName();
    }
    return ret;
}

void SendDataWithRtsCtsFrameExchange::doStep(int step)
{
    switch (step) {
        case 0: transmitFrame(dupPacketAndControlInfo(rtsFrame)); break;
        case 1: expectReplyRxStartWithin(utils->getCtsEarlyTimeout()); break;
        case 2: transmitFrame(dupPacketAndControlInfo(dataOrMgmtFrame), params->getSifsTime()); break;
        case 3: expectReplyRxStartWithin(utils->getAckEarlyTimeout()); break;
        case 4: /*statistics->frameTransmissionSuccessful(dataFrame, longRetryCount);*/ succeed(); break;
        default: ASSERT(false);
    }
}

FrameExchangeState SendDataWithRtsCtsFrameExchange::processReply(int step, Ieee80211Frame *frame)
{
    switch (step) {
        case 1:
            if (utils->isCts(frame)) {
                return FrameExchangeState(FrameExchangeState::ACCEPTED, defaultAccessCategory, dataOrMgmtFrame, rtsFrame);
            }
            else
                return FrameExchangeState(FrameExchangeState::IGNORED, defaultAccessCategory, dataOrMgmtFrame, rtsFrame);
        case 3:
            if (utils->isAck(frame)) {
                return FrameExchangeState(FrameExchangeState::ACCEPTED, defaultAccessCategory, dataOrMgmtFrame, dataOrMgmtFrame);
            }
            else
                return FrameExchangeState(FrameExchangeState::IGNORED, defaultAccessCategory, dataOrMgmtFrame, dataOrMgmtFrame);
        default: ASSERT(false);
        return FrameExchangeState::DONT_CARE;
    }
}

FrameExchangeState SendDataWithRtsCtsFrameExchange::processTimeout(int step)
{
    switch (step) {
        return transmissionFailed(dataOrMgmtFrame, rtsFrame);
        return transmissionFailed(dataOrMgmtFrame, dataOrMgmtFrame);
        default: ASSERT(false);
    }
    return FrameExchangeState::DONT_CARE;
}

FrameExchangeState SendDataWithRtsCtsFrameExchange::transmissionFailed(Ieee80211DataOrMgmtFrame *dataOrMgmtFrame, Ieee80211Frame* failedFrame)
{
    if (failedFrame->getType() == ST_DATA)
        failedFrame->setRetry(true);
    gotoStep(0);
    return FrameExchangeState(FrameExchangeState::TIMEOUT, defaultAccessCategory, dataOrMgmtFrame, failedFrame);
}

//------------------------------

SendMulticastDataFrameExchange::SendMulticastDataFrameExchange(FrameExchangeContext *context, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex, AccessCategory accessCategory) :
    FrameExchange(context), dataOrMgmtFrame(dataFrame), txIndex(txIndex), accessCategory(accessCategory)
{
    ASSERT(utils->isBroadcastOrMulticast(dataFrame));
    dataFrame->setDuration(0);
}

SendMulticastDataFrameExchange::~SendMulticastDataFrameExchange()
{
    delete dataOrMgmtFrame;
}

std::string SendMulticastDataFrameExchange::info() const
{
    return dataOrMgmtFrame ? std::string("frame=") + dataOrMgmtFrame->getName() : "";
}

FrameExchangeState SendMulticastDataFrameExchange::handleSelfMessage(cMessage *msg)
{
    ASSERT(false);
    return FrameExchangeState::DONT_CARE;
}

void SendMulticastDataFrameExchange::startFrameExchange()
{
    EV_DETAIL << "Starting frame exchange " << getClassName() << std::endl;
    tx->transmitFrame(dupPacketAndControlInfo(dataOrMgmtFrame));
}

void SendMulticastDataFrameExchange::continueFrameExchange()
{
    throw cRuntimeError("It is not allowed to continue a multicast frame exchange");
}

void SendMulticastDataFrameExchange::abortFrameExchange()
{
    throw cRuntimeError("It is not allowed to abort a multicast frame exchange.");
}

} // namespace ieee80211
} // namespace inet

