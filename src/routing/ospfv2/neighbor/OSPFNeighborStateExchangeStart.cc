//
// Copyright (C) 2006 Andras Babos and Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//


#include "OSPFNeighborStateExchangeStart.h"

#include "MessageHandler.h"
#include "OSPFArea.h"
#include "OSPFInterface.h"
#include "OSPFNeighborStateDown.h"
#include "OSPFNeighborStateExchange.h"
#include "OSPFNeighborStateInit.h"
#include "OSPFNeighborStateTwoWay.h"
#include "OSPFRouter.h"

namespace inet {

void OSPF::NeighborStateExchangeStart::processEvent(OSPF::Neighbor* neighbor, OSPF::Neighbor::NeighborEventType event)
{
    if ((event == OSPF::Neighbor::KILL_NEIGHBOR) || (event == OSPF::Neighbor::LINK_DOWN)) {
        MessageHandler* messageHandler = neighbor->getInterface()->getArea()->getRouter()->getMessageHandler();
        neighbor->reset();
        messageHandler->clearTimer(neighbor->getInactivityTimer());
        changeState(neighbor, new OSPF::NeighborStateDown, this);
    }
    if (event == OSPF::Neighbor::INACTIVITY_TIMER) {
        neighbor->reset();
        if (neighbor->getInterface()->getType() == OSPF::Interface::NBMA) {
            MessageHandler* messageHandler = neighbor->getInterface()->getArea()->getRouter()->getMessageHandler();
            messageHandler->startTimer(neighbor->getPollTimer(), neighbor->getInterface()->getPollInterval());
        }
        changeState(neighbor, new OSPF::NeighborStateDown, this);
    }
    if (event == OSPF::Neighbor::ONEWAY_RECEIVED) {
        neighbor->reset();
        changeState(neighbor, new OSPF::NeighborStateInit, this);
    }
    if (event == OSPF::Neighbor::HELLO_RECEIVED) {
        MessageHandler* messageHandler = neighbor->getInterface()->getArea()->getRouter()->getMessageHandler();
        messageHandler->clearTimer(neighbor->getInactivityTimer());
        messageHandler->startTimer(neighbor->getInactivityTimer(), neighbor->getRouterDeadInterval());
    }
    if (event == OSPF::Neighbor::IS_ADJACENCY_OK) {
        if (!neighbor->needAdjacency()) {
            neighbor->reset();
            changeState(neighbor, new OSPF::NeighborStateTwoWay, this);
        }
    }
    if (event == OSPF::Neighbor::DD_RETRANSMISSION_TIMER) {
        MessageHandler* messageHandler = neighbor->getInterface()->getArea()->getRouter()->getMessageHandler();
        neighbor->retransmitDatabaseDescriptionPacket();
        messageHandler->startTimer(neighbor->getDDRetransmissionTimer(), neighbor->getInterface()->getRetransmissionInterval());
    }
    if (event == OSPF::Neighbor::NEGOTIATION_DONE) {
        neighbor->createDatabaseSummary();
        neighbor->sendDatabaseDescriptionPacket();
        MessageHandler* messageHandler = neighbor->getInterface()->getArea()->getRouter()->getMessageHandler();
        messageHandler->clearTimer(neighbor->getDDRetransmissionTimer());
        changeState(neighbor, new OSPF::NeighborStateExchange, this);
    }
}


} // namespace inet

