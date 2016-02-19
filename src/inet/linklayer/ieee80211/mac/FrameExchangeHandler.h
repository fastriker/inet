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

#ifndef __INET_FRAMEEXCHANGEHANDLER_H
#define __INET_FRAMEEXCHANGEHANDLER_H

#include "IFrameExchangeHandler.h"

namespace inet {
namespace ieee80211 {

class INET_API FrameExchangeHandler : public IFrameExchangeHandler
{
    protected:
        AccessCategory channelOwner;
        IFrameExchange *frameExchange = nullptr;
        IUpperMac *upperMac = nullptr;
        UpperMacTxRetryHandler *txRetryHandler = nullptr;

    protected:
        virtual void startFrameExchange(Ieee80211DataOrMgmtFrame *frame, int txIndex, AccessCategory ac);
        virtual void frameExchangeFinished();
        virtual void frameTransmissionFailed(FrameExchangeState state);
        virtual void frameTransmissionSucceeded(FrameExchangeState state);

    public:
        virtual void channelAccessGranted(int txIndex) override;
        virtual bool processLowerFrameIfPossible(Ieee80211Frame *frame) override;
        virtual void transmissionComplete() override;
        virtual void corruptedOrNotForUsFrameReceived() override;
        virtual void handleMessage(cMessage *msg) override;

        FrameExchangeHandler(IUpperMac *upperMac) : upperMac(upperMac) {}
};

} /* namespace ieee80211 */
} /* namespace inet */

#endif // __INET_FRAMEEXCHANGEHANDLER_H
