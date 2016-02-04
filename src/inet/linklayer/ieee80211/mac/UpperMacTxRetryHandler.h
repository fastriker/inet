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

#ifndef __INET_UPPERMACTXRETRYHANDLER_H
#define __INET_UPPERMACTXRETRYHANDLER_H

#include "inet/common/INETDefs.h"
#include "AccessCategory.h"
#include "IMacParameters.h"
#include "inet/linklayer/ieee80211/mac/Ieee80211Frame_m.h"
#include "IFrameExchange.h"

namespace inet {
namespace ieee80211 {


//
// References: 9.19.2.6 Retransmit procedures (IEEE 802.11-2012 STD)
//             802.11 Reference Design: Recovery Procedures and Retransmit Limits
//             (https://warpproject.org/trac/wiki/802.11/MAC/Lower/Retransmissions)
//
class INET_API UpperMacTxRetryHandler
{
    protected:
        IMacParameters *params = nullptr;
        std::map<long int, int> shortRetryCounter; // msg id to retry counter
        std::map<long int, int> longRetryCounter;

        int stationLongRetryCounter = 0;
        int stationShortRetryCounter = 0;
        AccessCategory ac;
        int cw = 0;

    protected:
        void incrementCounter(Ieee80211Frame* frame, std::map<long int, int>& retryCounter);
        void incrementStationSrc();
        void incrementStationLrc();
        void resetStationSrc() { stationShortRetryCounter = 0; }
        void resetStationLrc() { stationLongRetryCounter = 0; }
        void resetContentionWindow() { cw = params->getCwMin(ac); }
        int doubleCw(int cw);
        int getRc(Ieee80211Frame* frame, std::map<long int, int>& retryCounter);
        bool isManagementFrame(Ieee80211Frame *frame);
        bool isMulticastFrame(Ieee80211Frame *frame);
        bool isDataFrame(Ieee80211Frame *frame);
        void multicastFrameTransmitted();

    public:
        // The contention window (CW) parameter shall take an initial value of aCWmin.
        UpperMacTxRetryHandler(IMacParameters *params, AccessCategory ac) :
            params(params), ac(ac), cw(params->getCwMin(ac)) {}

        bool isRetryPossible(Ieee80211Frame* dataFrame, Ieee80211Frame *failedFrame);
        void frameTransmissionSucceeded(Ieee80211Frame* frame);
        void frameTransmissionFailed(Ieee80211Frame *frame, Ieee80211Frame *failedFrame);
        int getCw() { return cw; }

};

} /* namespace ieee80211 */
} /* namespace inet */

#endif // ifndef __INET_UPPERMACTXRETRYHANDLER_H
