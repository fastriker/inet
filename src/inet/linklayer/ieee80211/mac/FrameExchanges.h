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
        Ieee80211DataOrMgmtFrame *dataOrMgmtFrame = nullptr;

    protected:
        virtual void doStep(int step) override;

        virtual FrameExchangeState transmissionFailed();
        virtual FrameExchangeState processReply(int step, Ieee80211Frame *frame) override;
        virtual FrameExchangeState processTimeout(int step) override;
    public:
        SendDataWithAckFrameExchange(FrameExchangeContext *context, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex);
        ~SendDataWithAckFrameExchange();
        virtual std::string info() const override;
        virtual Ieee80211DataOrMgmtFrame *getDataOrMgmtFrame() { return dataOrMgmtFrame; }
};

class INET_API SendDataWithRtsCtsFrameExchange : public StepBasedFrameExchange
{
    protected:
        Ieee80211DataOrMgmtFrame *dataOrMgmtFrame = nullptr;
        Ieee80211RTSFrame *rtsFrame = nullptr;

    protected:
        virtual void doStep(int step) override;
        virtual FrameExchangeState processReply(int step, Ieee80211Frame *frame) override;
        virtual FrameExchangeState processTimeout(int step) override;
        virtual FrameExchangeState transmissionFailed(Ieee80211DataOrMgmtFrame *dataOrMgmtFrame, Ieee80211Frame *failedFrame);

    public:
        SendDataWithRtsCtsFrameExchange(FrameExchangeContext *context, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex);
        ~SendDataWithRtsCtsFrameExchange();
        virtual std::string info() const override;
        virtual Ieee80211DataOrMgmtFrame *getDataOrMgmtFrame() { return dataOrMgmtFrame; }
};

class INET_API SendMulticastDataFrameExchange : public FrameExchange
{
    protected:
        Ieee80211DataOrMgmtFrame *dataOrMgmtFrame;
        int txIndex;

    public:
        SendMulticastDataFrameExchange(FrameExchangeContext *context, Ieee80211DataOrMgmtFrame *dataFrame, int txIndex);
        ~SendMulticastDataFrameExchange();
        virtual void startFrameExchange() override;
        virtual void continueFrameExchange() override;
        virtual void abortFrameExchange() override;
        virtual FrameExchangeState handleSelfMessage(cMessage* timer) override;
        virtual std::string info() const override;
        virtual bool isFinished() override { return true; }
        virtual Ieee80211DataOrMgmtFrame *getDataOrMgmtFrame() { return dataOrMgmtFrame; }
        virtual Ieee80211Frame *getNextFrameWaitingForTransmission() { return dataOrMgmtFrame; }
};

} // namespace ieee80211
} // namespace inet

#endif

