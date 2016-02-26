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

#ifndef __INET_EDCAUPPERMAC_H
#define __INET_EDCAUPPERMAC_H

#include "UpperMacBase.h"
#include "FrameExchanges.h"

namespace inet {
namespace ieee80211 {

class EdcaUpperMac : public UpperMacBase, public IUpperMac
{
    protected:
        int numACs = 4;
        Foo *foos;
        int maxQueueSize; // TODO: use queue subclass that supports maxQueueSize
        AccessCategory channelOwner = AccessCategory(-1);

    protected:
        virtual void initialize() override;
        virtual void handleMessage(cMessage* msg) override;
        virtual AccessCategory classifyFrame(Ieee80211DataOrMgmtFrame *frame);
        virtual AccessCategory mapTidToAc(int tid);
        virtual void deleteFrameExchange(Foo& foo);

    protected:
        virtual void corruptedOrNotForUsFrameReceived() override;
        virtual bool processLowerFrameIfPossible(Ieee80211Frame *frame) override;
        virtual void releaseChannel(IContention *contention) override;

    public:
        virtual void upperFrameReceived(Ieee80211DataOrMgmtFrame *frame) override;
        virtual void lowerFrameReceived(Ieee80211Frame *frame) override;

        virtual void transmissionComplete() override;
        virtual void internalCollision(int txIndex) override;
        virtual void channelAccessGranted(int txIndex) override;

        virtual ~EdcaUpperMac();
};

} /* namespace ieee80211 */
} /* namespace inet */

#endif // ifndef __INET_EDCAUPPERMAC_H
