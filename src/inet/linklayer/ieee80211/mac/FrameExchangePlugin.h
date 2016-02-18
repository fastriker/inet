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

#ifndef __INET_FRAMEEXCHANGEPLUGIN_H
#define __INET_FRAMEEXCHANGEPLUGIN_H

#include "MacPlugin.h"
#include "FrameExchange.h"

namespace inet {
namespace ieee80211 {

class FrameExchangePlugin : public MacPlugin {
    public:
        FrameExchangePlugin(cSimpleModule *ownerModule) : MacPlugin(ownerModule) {}
        virtual FrameExchangeState handleSelfMessage(cMessage *msg) = 0;
};

} /* namespace ieee80211 */
} /* namespace inet */

#endif // __INET_FRAMEEXCHANGEPLUGIN_H
