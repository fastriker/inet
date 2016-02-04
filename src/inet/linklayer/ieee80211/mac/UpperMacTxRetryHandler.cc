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

#include "UpperMacTxRetryHandler.h"

namespace inet {
namespace ieee80211 {

//
// The CW shall take the next value in the series every time an
// unsuccessful attempt to transmit an MPDU causes either STA retry
// counter to increment, until the CW reaches the value of aCWmax.
//
//
// The CW shall be reset to aCWmin after every successful attempt to transmit
// a frame containing all or part of an MSDU or MMPDU, when SLRC reaches
// dot11LongRetryLimit, or when SSRC reaches dot11ShortRetryLimit.
//
void UpperMacTxRetryHandler::incrementStationSrc()
{
    stationShortRetryCounter++;
    if (stationShortRetryCounter == params->getShortRetryLimit()) // 9.3.3 Random backoff time
        resetContentionWindow();
    else
        cw = doubleCw(cw);
}

void UpperMacTxRetryHandler::incrementStationLrc()
{
    stationLongRetryCounter++;
    if (stationLongRetryCounter == params->getLongRetryLimit()) // 9.3.3 Random backoff time
        resetContentionWindow();
    else
        cw = doubleCw(cw);
}

void UpperMacTxRetryHandler::incrementCounter(Ieee80211Frame* frame, std::map<long int, int>& retryCounter)
{
    int id = frame->getTreeId();
    if (retryCounter.find(id) != retryCounter.end())
        retryCounter[id]++;
    else
        retryCounter.insert(std::make_pair(id, 0));
}

int UpperMacTxRetryHandler::doubleCw(int cw)
{
    int newCw = 2 * cw + 1;
    if (newCw > params->getCwMax(ac))
        return params->getCwMax(ac);
    return newCw;
}


bool UpperMacTxRetryHandler::isManagementFrame(Ieee80211Frame* frame)
{
    int type = frame->getType();
    return type >= ST_ASSOCIATIONREQUEST && type <= ST_NOACKACTION;
}

bool UpperMacTxRetryHandler::isMulticastFrame(Ieee80211Frame* frame)
{
    if (dynamic_cast<Ieee80211OneAddressFrame*>(frame))
    {
        Ieee80211OneAddressFrame *oneAddressFrame = dynamic_cast<Ieee80211OneAddressFrame*>(frame);
        return oneAddressFrame->getReceiverAddress().isBroadcast();
    }
    return false;
}

void UpperMacTxRetryHandler::multicastFrameTransmitted()
{
    resetStationLrc();
    resetStationSrc();
}

bool UpperMacTxRetryHandler::isDataFrame(Ieee80211Frame* frame)
{
    return frame->getType() == ST_DATA || frame->getType() == ST_DATA_WITH_QOS;
}

//
// This SRC and the SSRC shall be reset when a MAC frame of length less than or equal
// to dot11RTSThreshold succeeds for that MPDU of type Data or MMPDU.

// This LRC and the SLRC shall be reset when a MAC frame of length greater than dot11RTSThreshold
// succeeds for that MPDU of type Data or MMPDU.
//
// The SSRC shall be reset to 0 when a CTS frame is received in response to an RTS frame
//
// The CW shall be reset to aCWmin after every successful attempt to transmit a frame containing
// all or part of an MSDU or MMPDU
//
// The SSRC shall be reset to 0 when a CTS frame is received in response to an RTS
// frame, when a BlockAck frame is received in response to a BlockAckReq frame, when an ACK frame is
// received in response to the transmission of a frame of length greater* than dot11RTSThreshold containing all or
// part of an MSDU or MMPDU, or when a frame with a group address in the Address1 field is transmitted. The
// SLRC shall be reset to 0 when an ACK frame is received in response to transmission of a frame containing all
// or part of an MSDU or MMPDU of , or when a frame with a group address in the Address1 field is transmitted.
//
// Note: * This is obviously wrong.

void UpperMacTxRetryHandler::frameTransmissionSucceeded(Ieee80211Frame* frame)
{
    if (isMulticastFrame(frame))
        multicastFrameTransmitted();
    else if (frame->getType() == ST_RTS)
        resetStationSrc();
    else if (isDataFrame(frame) || isManagementFrame(frame))
    {
        if (frame->getByteLength() >= params->getRtsThreshold())
            resetStationLrc();
        else
            resetStationSrc();

        resetContentionWindow();
    }
    else
        throw cRuntimeError("frameTransmissionSucceeded(): Unknown frame type = %d", frame->getType());

}

//
// The SRC for an MPDU of type Data or MMPDU and the SSRC shall be incremented every
// time transmission of a MAC frame of length less than or equal to dot11RTSThreshold
// fails for that MPDU of type Data or MMPDU.

// The LRC for an MPDU of type Data or MMPDU and the SLRC shall be incremented every time
// transmission of a MAC frame of length greater than dot11RTSThreshold fails for that MPDU
// of type Data or MMPDU.
//
void UpperMacTxRetryHandler::frameTransmissionFailed(Ieee80211Frame* dataFrame, Ieee80211Frame *failedFrame)
{
    if (failedFrame->getType() == ST_RTS)
    {
        incrementStationSrc();
        incrementCounter(dataFrame, shortRetryCounter);
    }
    else if (failedFrame->getType() == ST_DATA || failedFrame->getType() == ST_DATA_WITH_QOS)
    {
        if (dataFrame->getByteLength() >= params->getRtsThreshold())
        {
            incrementStationLrc();
            incrementCounter(dataFrame, longRetryCounter);
        }
        else
        {
            incrementStationSrc();
            incrementCounter(dataFrame, shortRetryCounter);
        }
    }
//    else if (failedFrame->getType() == ST_DATA_WITH_QOS)
//    {
//        // TODO: A-MSDU, Block Ack
//    }
    else
        throw cRuntimeError("frameTransmissionFailed(): Unknown frame type = %d", dataFrame->getType());
}

//
// Retries for failed transmission attempts shall continue until the SRC for the MPDU of type
// Data or MMPDU is equal to dot11ShortRetryLimit or until the LRC for the MPDU of type Data
// or MMPDU is equal to dot11LongRetryLimit. When either of these limits is reached, retry attempts
// shall cease, and the MPDU of type Data (and any MSDU of which it is a part) or MMPDU shall be discarded.
//
bool UpperMacTxRetryHandler::isRetryPossible(Ieee80211Frame* dataFrame, Ieee80211Frame *failedFrame)
{
    if (failedFrame->getType() == ST_RTS)
        return getRc(dataFrame, shortRetryCounter) < params->getShortRetryLimit();
    else if (failedFrame->getType() == ST_DATA || failedFrame->getType() == ST_DATA_WITH_QOS)
    {
        if (dataFrame->getByteLength() >= params->getRtsThreshold())
            return getRc(dataFrame, longRetryCounter) < params->getLongRetryLimit();
        else
            return getRc(dataFrame, shortRetryCounter) < params->getShortRetryLimit();
    }
    else
        throw cRuntimeError("isRetryPossible(): Unknown frame type = %d", failedFrame->getType());
}

int UpperMacTxRetryHandler::getRc(Ieee80211Frame* frame, std::map<long int, int>& retryCounter)
{
    auto count = retryCounter.find(frame->getTreeId());
    if (count != retryCounter.end())
        return count->second;
    else
        throw cRuntimeError("The retry counter entry doesn't exist for message id: ", frame->getId());
    return 0;
}

} /* namespace ieee80211 */
} /* namespace inet */
