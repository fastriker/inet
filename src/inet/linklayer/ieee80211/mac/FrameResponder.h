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

#ifndef __INET_FRAMERESPONDER_H
#define __INET_FRAMERESPONDER_H

#include "IFrameResponder.h"
#include "ITx.h"
#include "MacUtils.h"
#include "MacParameters.h"

namespace inet {
namespace ieee80211 {

class INET_API FrameResponder : public IFrameResponder
{
    protected:
        IMacParameters *params = nullptr;
        MacUtils *utils = nullptr;
        ITx *tx = nullptr;

    protected:
        void sendAck(Ieee80211DataOrMgmtFrame *frame);
        void sendCts(Ieee80211RTSFrame *frame);

    public:
        virtual bool respondToLowerFrameIfPossible(Ieee80211Frame *frame) override;
        FrameResponder(IMacParameters *params, MacUtils *utils, ITx *tx) :
            params(params), utils(utils), tx(tx) {}
};

} /* namespace ieee80211 */
} /* namespace inet */

#endif // __INET_FRAMERESPONDER_H
