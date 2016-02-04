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

#ifndef __INET_FRAMEEXCHANGE_H
#define __INET_FRAMEEXCHANGE_H

#include "IFrameExchange.h"
#include "MacPlugin.h"
#include "ITxCallback.h"
#include "AccessCategory.h"

namespace inet {
namespace ieee80211 {

class IMacParameters;
class MacUtils;
class ITx;
class IContention;
class IRx;
class IStatistics;

class INET_API FrameExchangeContext
{
    public:
        cSimpleModule *ownerModule = nullptr;
        IMacParameters *params = nullptr;
        MacUtils *utils = nullptr;
        ITx *tx = nullptr;
        IRx *rx = nullptr;
        IStatistics *statistics = nullptr;
};

/**
 * The default base class for implementing frame exchanges (see IFrameExchange).
 */
class INET_API FrameExchange : public MacPlugin, public IFrameExchange, public ITxCallback
{
    protected:
        IMacParameters *params;
        MacUtils *utils;
        ITx *tx;
        IRx *rx;
        IStatistics *statistics;
        IFinishedCallback *upperMac = nullptr;

    protected:
        virtual void transmitFrame(Ieee80211Frame *frame, simtime_t ifs);
        virtual void reportSuccess();
        virtual void reportFailure();

        virtual FrameProcessingResult lowerFrameReceived(Ieee80211Frame *frame) override;
        virtual void corruptedOrNotForUsFrameReceived() override;

    public:
        FrameExchange(FrameExchangeContext *context, IFinishedCallback *callback);
        virtual AccessCategory getAc() = 0;
        virtual ~FrameExchange();
};

class INET_API StepBasedFrameExchange : public FrameExchange
{
    protected:
        enum Operation { NONE, TRANSMIT_FRAME, EXPECT_FULL_REPLY, EXPECT_REPLY_RXSTART, GOTO_STEP, FAIL, SUCCEED };
        enum Status { INPROGRESS, SUCCEEDED, FAILED };
        int defaultTxIndex;
        AccessCategory defaultAccessCategory;
        int step = 0;
        Operation operation = NONE;
        Status status = INPROGRESS;
        cMessage *timeoutMsg = nullptr;
        int gotoTarget = -1;

    protected:
        // to be redefined by user
        virtual void doStep(int step) = 0;
        virtual FrameProcessingResult processReply(int step, Ieee80211Frame *frame) = 0; // true = frame accepted as reply and processing will continue on next step
        virtual void processTimeout(int step) = 0;

        // operations that can be called from doStep()
        virtual void transmitFrame(Ieee80211Frame *frame);
        virtual void transmitFrame(Ieee80211Frame *frame, simtime_t ifs);
        virtual void expectFullReplyWithin(simtime_t timeout);  // may invoke processReply() and processTimeout()
        virtual void expectReplyRxStartWithin(simtime_t timeout); // may invoke processReply() and processTimeout()
        virtual void gotoStep(int step); // ~setNextStep()
        virtual void fail();
        virtual void succeed();

        // internal
        virtual void proceed();
        virtual void cleanup();
        virtual void setOperation(Operation type);
        virtual void logStatus(const char *what);
        virtual void checkOperation(Operation stepType, const char *where);
        virtual void handleTimeout();
        static const char *statusName(Status status);
        static const char *operationName(Operation operation);
        static const char *operationFunctionName(Operation operation);

    public:
        StepBasedFrameExchange(FrameExchangeContext *context, IFinishedCallback *callback, int txIndex, AccessCategory accessCategory);
        virtual ~StepBasedFrameExchange();
        std::string info() const override;
        virtual void startFrameExchange() override;
        virtual void continueFrameExchange() override;
        virtual void abortFrameExchange() override;
        virtual FrameProcessingResult lowerFrameReceived(Ieee80211Frame *frame) override;
        virtual void corruptedOrNotForUsFrameReceived() override;
        virtual void transmissionComplete() override;
        virtual void handleSelfMessage(cMessage *timer) override;
        virtual AccessCategory getAc() override { return defaultAccessCategory; }
};

} // namespace ieee80211
} // namespace inet

#endif

