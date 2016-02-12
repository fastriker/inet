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

#ifndef __INET_IFRAMEEXCHANGE_H
#define __INET_IFRAMEEXCHANGE_H

#include "inet/common/INETDefs.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "AccessCategory.h"

namespace inet {
namespace ieee80211 {

class Ieee80211Frame;

/**
 * Abstract interface for frame exchange classes. Frame exchanges are a basic
 * building block of UpperMac (see IUpperMac), and coordinate frame sequences.
 */
class INET_API IFrameExchange
{
    public:
        class INET_API IFrameExchangeCallback {
            public:
                virtual void frameExchangeFinished(IFrameExchange *what, bool successful) = 0;
                virtual void frameTransmissionFailed(IFrameExchange *what, Ieee80211Frame *dataFrame, Ieee80211Frame *failedFrame, AccessCategory ac) = 0;
                virtual void frameTransmissionSucceeded(IFrameExchange *what, Ieee80211Frame *frame, AccessCategory ac) = 0;
                virtual ~IFrameExchangeCallback() {}
        };

        enum FrameProcessingResult { ACCEPTED, IGNORED, TIMEOUT }; // TODO: step result

        class INET_API FrameExchangeState
        {
            public:
                static FrameExchangeState DONT_CARE;

                FrameProcessingResult result = IGNORED;
                AccessCategory ac = AC_LEGACY;
                Ieee80211DataOrMgmtFrame *dataOrMgmtFrame = nullptr;
                Ieee80211Frame *transmittedFrame = nullptr;
                bool successfullyTransmitted = false;

                FrameExchangeState(FrameProcessingResult result, AccessCategory ac, Ieee80211DataOrMgmtFrame *dataOrMgmtFrame, Ieee80211Frame *transmittedFrame, bool successfullyTransmitted) :
                    result(result), ac(ac), dataOrMgmtFrame(dataOrMgmtFrame), transmittedFrame(transmittedFrame), successfullyTransmitted(successfullyTransmitted) {}
        };


    public:
        virtual ~IFrameExchange() {}
        virtual void startFrameExchange() = 0;
        virtual void continueFrameExchange() = 0;
        virtual void abortFrameExchange() = 0;
        virtual Ieee80211DataOrMgmtFrame *getDataFrame() = 0;
        virtual Ieee80211Frame *getFirstFrame() = 0;
        virtual FrameExchangeState lowerFrameReceived(Ieee80211Frame *frame) = 0;
        virtual void corruptedOrNotForUsFrameReceived() = 0;
        virtual AccessCategory getAc() = 0;

        /////
        virtual FrameExchangeState newHandleSelfMessage(cMessage *msg) = 0;
        virtual bool isSucceeded() = 0;
        virtual bool isFinished() = 0;
};

} // namespace ieee80211
} // namespace inet

#endif

