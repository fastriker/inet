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

#ifndef __INET_DCFUPPERMAC_H
#define __INET_DCFUPPERMAC_H

#include "IUpperMac.h"
#include "IFrameExchange.h"
#include "AccessCategory.h"
#include "ITxCallback.h"
#include "inet/physicallayer/ieee80211/mode/IIeee80211Mode.h"
#include "UpperMacTxRetryHandler.h"
#include "IFrameExchangeHandler.h"
#include "IFrameResponder.h"

using namespace inet::physicallayer;

namespace inet {
namespace ieee80211 {

class IRx;
class IContentionCallback;
class ITxCallback;
class Ieee80211Mac;
class Ieee80211RTSFrame;
class IMacQoSClassifier;
class IMacParameters;
class MacUtils;
class ITx;
class IContention;
class IDuplicateDetector;
class IFragmenter;
class IReassembly;
class IRateSelection;
class IRateControl;
class IStatistics;
class IMsduAggregation;

/**
 * UpperMac for DCF mode.
 */
class INET_API DcfUpperMac : public cSimpleModule, public IUpperMac, public IContentionCallback
{
    public:
        typedef std::list<Ieee80211DataOrMgmtFrame*> Ieee80211DataOrMgmtFrameList;

    protected:
        IMacParameters *params = nullptr;
        MacUtils *utils = nullptr;
        Ieee80211Mac *mac = nullptr;
        IRx *rx = nullptr;
        ITx *tx = nullptr;
        IContention **contention = nullptr;

        int maxQueueSize;
        int fragmentationThreshold = 2346;

        cQueue *transmissionQueue = nullptr;
        IDuplicateDetector *duplicateDetection = nullptr;
        IMsduAggregation *msduAggregator = nullptr;
        IFragmenter *fragmenter = nullptr;
        IReassembly *reassembly = nullptr;
        IRateSelection *rateSelection = nullptr;
        IRateControl *rateControl = nullptr;
        IStatistics *statistics = nullptr;

        IFrameExchangeHandler *frameExchangeHandler = nullptr;
        IFrameResponder *frameResponder = nullptr;

    protected:
        virtual void initialize() override;
        virtual IMacParameters *extractParameters(const IIeee80211Mode *slowestMandatoryMode);
        virtual void handleMessage(cMessage *msg) override;
        virtual void enqueue(Ieee80211DataOrMgmtFrame *frame, AccessCategory ac);
        virtual Ieee80211DataOrMgmtFrame *aggregateIfPossible(AccessCategory ac);
        virtual bool fragmentIfPossible(Ieee80211DataOrMgmtFrame* nextFrame, bool aMsduPresent, AccessCategory ac);
        virtual void assignSequenceNumber(Ieee80211DataOrMgmtFrame *frame);
        virtual void explodeAggregatedFrame(Ieee80211DataFrame *frame);
        virtual bool sendUpIfNecessary(Ieee80211Frame *frame);
        virtual AccessCategory classifyFrame(Ieee80211DataOrMgmtFrame *frame);
        virtual AccessCategory mapTidToAc(int tid);

    public:
        DcfUpperMac();
        virtual ~DcfUpperMac();
        virtual void upperFrameReceived(Ieee80211DataOrMgmtFrame *frame) override;
        virtual void lowerFrameReceived(Ieee80211Frame *frame) override;
        virtual void transmissionComplete() override;
        virtual void channelAccessGranted(int txIndex) override;
        virtual void internalCollision(int txIndex) override;
        virtual void corruptedOrNotForUsFrameReceived();
        virtual void releaseChannel(AccessCategory ac) override;
        virtual void startContention(AccessCategory ac, int cw) override;
        virtual Ieee80211DataOrMgmtFrame *dequeueNextFrameToTransmit(AccessCategory ac) override;
        virtual bool hasMoreFrameToTransmit(AccessCategory ac) override;
        virtual Ieee80211DataOrMgmtFrame *getFirstFrame(AccessCategory ac) override;
        virtual void deleteFirstFrame(AccessCategory ac) override;

};

} // namespace ieee80211
} // namespace inet

#endif

