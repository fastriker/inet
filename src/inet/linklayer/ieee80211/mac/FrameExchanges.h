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

#ifndef __INET_FRAMEEXCHANGES_H
#define __INET_FRAMEEXCHANGES_H

#include "FrameExchange.h"

namespace inet {
namespace ieee80211 {

class Ieee80211DataOrMgmtFrame;

class INET_API SendDataWithAckFrameExchange : public StepBasedFrameExchange
{
    protected:
        Ieee80211DataOrMgmtFrame *dataFrame = nullptr;
        int retryCount = 0;
    protected:
        virtual void doStep(int step) override;

        virtual FrameExchangeState transmissionFailed();
        virtual FrameExchangeState processReply(int step, Ieee80211Frame *frame) override;
        virtual FrameExchangeState processTimeout(int step) override;
    public:
        SendDataWithAckFrameExchange(FrameExchangeContext *context, IFrameExchangeCallback *callback, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex, AccessCategory accessCategory);
        ~SendDataWithAckFrameExchange();
        virtual Ieee80211DataOrMgmtFrame *getDataFrame() override { return dataFrame; }
        virtual Ieee80211Frame *getFirstFrame() override { return dataFrame; }
        virtual std::string info() const override;
};

class INET_API SendDataWithRtsCtsFrameExchange : public StepBasedFrameExchange
{
    protected:
        Ieee80211DataOrMgmtFrame *dataFrame = nullptr;
        Ieee80211RTSFrame *rtsFrame = nullptr;

    protected:
        virtual void doStep(int step) override;
        virtual FrameExchangeState processReply(int step, Ieee80211Frame *frame) override;
        virtual FrameExchangeState processTimeout(int step) override;
        virtual FrameExchangeState transmissionFailed(Ieee80211DataOrMgmtFrame *dataOrMgmtFrame, Ieee80211Frame *failedFrame);

    public:
        SendDataWithRtsCtsFrameExchange(FrameExchangeContext *context, IFrameExchangeCallback *callback, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex, AccessCategory accessCategory);
        ~SendDataWithRtsCtsFrameExchange();
        virtual Ieee80211DataOrMgmtFrame *getDataFrame() override { return dataFrame; }
        virtual Ieee80211Frame *getFirstFrame() override { return rtsFrame; }
        virtual std::string info() const override;
};

class INET_API SendMulticastDataFrameExchange : public FrameExchange
{
    protected:
        Ieee80211DataOrMgmtFrame *dataFrame;
        int txIndex;
        AccessCategory accessCategory;

    public:
        SendMulticastDataFrameExchange(FrameExchangeContext *context, IFrameExchangeCallback *callback, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex, AccessCategory accessCategory);
        ~SendMulticastDataFrameExchange();
        virtual void startFrameExchange() override;
        virtual void continueFrameExchange() override;
        virtual void abortFrameExchange() override;
        virtual void transmissionComplete() override;
        virtual void handleSelfMessage(cMessage* timer) override;
        virtual std::string info() const override;
        virtual Ieee80211DataOrMgmtFrame *getDataFrame() override { return dataFrame; }
        virtual Ieee80211Frame *getFirstFrame() override { return dataFrame; }
        virtual AccessCategory getAc() override { return accessCategory; }
        virtual FrameExchangeState newHandleSelfMessage(cMessage *msg) override {};
};

} // namespace ieee80211
} // namespace inet

#endif

