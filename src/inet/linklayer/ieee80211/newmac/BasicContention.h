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

#ifndef __INET_BASICCONTENTION_H
#define __INET_BASICCONTENTION_H

#include "IContention.h"
#include "ICollisionController.h"
#include "inet/physicallayer/contract/packetlevel/IRadio.h"

namespace inet {
namespace ieee80211 {

using namespace inet::physicallayer;

class IUpperMac;
class IMacRadioInterface;
class IRx;
class IStatistics;

class INET_API BasicContention : public cSimpleModule, public IContention, protected ICollisionController::ICallback
{
    public:
        enum State { IDLE, DEFER, IFS_AND_BACKOFF, OWNING };
        enum EventType { START, MEDIUM_STATE_CHANGED, CORRUPTED_FRAME_RECEIVED, TRANSMISSION_GRANTED, INTERNAL_COLLISION, CHANNEL_RELEASED };

    protected:
        IMacRadioInterface *mac;
        IUpperMac *upperMac;
        ICollisionController *collisionController;  // optional
        IStatistics *statistics;
        cMessage *startTxEvent = nullptr;  // in the absence of collisionController
        int txIndex;

        // current contention's parameters
        simtime_t ifs = SIMTIME_ZERO;
        simtime_t eifs = SIMTIME_ZERO;
        int cwMin = 0;
        int cwMax = 0;
        simtime_t slotTime;
        int retryCount = 0;
        IContentionCallback *callback = nullptr;

        cFSM fsm;
        simtime_t endEifsTime = SIMTIME_ZERO;
        int backoffSlots = 0;
        simtime_t scheduledTransmissionTime = SIMTIME_ZERO;
        simtime_t channelLastBusyTime = SIMTIME_ZERO;
        bool mediumFree = false;

    protected:
        virtual void initialize() override;
        virtual void handleMessage(cMessage *msg) override;
        virtual void transmissionGranted(int txIndex) override; // called back from collision controller
        virtual void internalCollision(int txIndex) override; // called back from collision controller

        virtual int computeCw(int cwMin, int cwMax, int retryCount);
        virtual void handleWithFSM(EventType event, cMessage *msg);
        virtual void scheduleTransmissionRequest();
        virtual void scheduleTransmissionRequestFor(simtime_t txStartTime);
        virtual void cancelTransmissionRequest();
        virtual void switchToEifs();
        virtual void computeRemainingBackoffSlots();
        virtual void updateDisplayString();
        const char *getEventName(EventType event);

    public:
        BasicContention() {}
        ~BasicContention();

        //TODO also add a switchToReception() method? because switching takes time, so we dont automatically switch to tx after completing a transmission! (as we may want to transmit immediate frames afterwards)
        virtual void startContention(simtime_t ifs, simtime_t eifs, int cwMin, int cwMax, simtime_t slotTime, int retryCount, IContentionCallback *callback) override;
        virtual void channelReleased() override;

        virtual void mediumStateChanged(bool mediumFree) override;
        virtual void corruptedFrameReceived() override;
        virtual bool isOwning() override;
        virtual bool isContentionInProgress() override;
};

} // namespace ieee80211
} // namespace inet

#endif

