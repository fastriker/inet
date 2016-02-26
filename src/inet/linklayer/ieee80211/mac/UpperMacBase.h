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

#ifndef __INET_UPPERMACBASE_H
#define __INET_UPPERMACBASE_H

#include "IUpperMac.h"
#include "IFrameExchange.h"
#include "inet/physicallayer/ieee80211/mode/IIeee80211Mode.h"
#include "UpperMacTxRetryHandler.h"
#include "IFrameResponder.h"
#include "ITxCallback.h"

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

class INET_API UpperMacBase : public cSimpleModule, public IContentionCallback
{
    protected:
        IMacParameters *params = nullptr; // TODO: move to the Foo struct
        MacUtils *utils = nullptr;
        Ieee80211Mac *mac = nullptr;
        IRx *rx = nullptr;
        ITx *tx = nullptr;

        IDuplicateDetector *duplicateDetection = nullptr;
        IMsduAggregation *msduAggregator = nullptr;
        IFragmenter *fragmenter = nullptr;
        IReassembly *reassembly = nullptr;
        IRateSelection *rateSelection = nullptr;
        IRateControl *rateControl = nullptr;
        IStatistics *statistics = nullptr;
        IFrameResponder *frameResponder = nullptr;

        int fragmentationThreshold = 2346; // TODO: remove

    public:
        struct Foo
        {
            // TODO: timing parameters from IMacParameters *params = nullptr;
            AccessCategory ac = AccessCategory(-1); // TODO: temporary member
            cQueue transmissionQueue;
            IFrameExchange *frameExchange = nullptr;
            UpperMacTxRetryHandler *txRetryHandler = nullptr;
            IContention *contention = nullptr;
        };

    protected:
        virtual void initialize() override;
        IMacParameters *extractParameters(const IIeee80211Mode *slowestMandatoryMode);

        // Aggregation
        virtual void sendUpAggregatedFrame(Ieee80211DataFrame* dataFrame);
        virtual Ieee80211DataOrMgmtFrame* aggregateIfPossible(cQueue *queue);

        // Fragmentation
        virtual bool fragmentIfNecessary(cQueue *queue, Ieee80211DataOrMgmtFrame* nextFrame, bool aMsduPresent);

        // Queue management
        virtual Ieee80211DataOrMgmtFrame* extractNextFrameToTransmit(cQueue *queue);

        // Sequence number assignment
        virtual void assignSequenceNumber(Ieee80211DataOrMgmtFrame* frame);

        // Contention
        virtual void startContention(Foo& foo);
        virtual void startContentionIfNecessary(Foo& foo);
        virtual void releaseChannel(IContention *contention);

        // Frame exchanges
        virtual void startFrameExchange(Foo& foo, int txIndex);
        virtual void frameTransmissionFailed(Foo& foo, Ieee80211DataOrMgmtFrame *dataOrMgmtFrame, Ieee80211Frame *transmittedFrame);
        virtual void frameTransmissionSucceeded(Foo& foo, Ieee80211Frame *transmittedFrame);
        virtual void frameExchangeFinished(Foo& foo);

        virtual bool sendUpIfNecessary(Ieee80211Frame* frame);

    protected:
        virtual void corruptedOrNotForUsFrameReceived() = 0;
        virtual bool processLowerFrameIfPossible(Ieee80211Frame *frame) = 0;

    public:
        virtual void lowerFrameReceived(Ieee80211Frame* frame);

};

} /* namespace ieee80211 */
} /* namespace inet */

#endif // ifndef __INET_UPPERMACBASE_H
