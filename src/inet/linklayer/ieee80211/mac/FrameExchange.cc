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

#include "FrameExchange.h"
#include "IMacParameters.h"
#include "IContention.h"
#include "ITx.h"
#include "IRx.h"
#include "Ieee80211Frame_m.h"

namespace inet {
namespace ieee80211 {

FrameExchangeState FrameExchangeState::DONT_CARE = FrameExchangeState(IGNORED, nullptr, nullptr);

FrameExchange::FrameExchange(FrameExchangeContext *context) :
    FrameExchangePlugin(context->ownerModule),
    params(context->params),
    utils(context->utils),
    tx(context->tx),
    rx(context->rx),
    statistics(context->statistics)
{
}

FrameExchange::~FrameExchange()
{
}

void FrameExchange::transmitFrame(Ieee80211Frame *frame, simtime_t ifs)
{
    nextFrameWatingForTransmmission = frame;
    tx->transmitFrame(frame, ifs);
}

FrameExchangeState FrameExchange::lowerFrameReceived(Ieee80211Frame *frame)
{
    return FrameExchangeState::DONT_CARE; // not ours
}

void FrameExchange::corruptedOrNotForUsFrameReceived()
{
    // we don't care
}

StepBasedFrameExchange::StepBasedFrameExchange(FrameExchangeContext *context, int txIndex) :
    FrameExchange(context), defaultTxIndex(txIndex)
{
}

StepBasedFrameExchange::~StepBasedFrameExchange()
{
    if (timeoutMsg)
        cancelAndDelete(timeoutMsg);
}

std::string StepBasedFrameExchange::info() const
{
    std::stringstream out;
    switch (status) {
        case SUCCEEDED: out << "SUCCEEDED in step " << step; break;
        case FAILED: out << "FAILED in step " << step; break;
        case INPROGRESS: out << "step " << step << ", operation=" << operationName(operation); break;
    }
    return out.str();
}

const char *StepBasedFrameExchange::statusName(Status status)
{
#define CASE(x) case x: return #x
    switch (status) {
        CASE(SUCCEEDED);
        CASE(FAILED);
        CASE(INPROGRESS);
        default: ASSERT(false); return "???";
    }
#undef CASE
}

const char *StepBasedFrameExchange::operationName(Operation operation)
{
#define CASE(x) case x: return #x
    switch (operation) {
        CASE(NONE);
        CASE(TRANSMIT_FRAME);
        CASE(EXPECT_FULL_REPLY);
        CASE(EXPECT_REPLY_RXSTART);
        CASE(GOTO_STEP);
        CASE(FAIL);
        CASE(SUCCEED);
        default: ASSERT(false); return "???";
    }
#undef CASE
}

const char *StepBasedFrameExchange::operationFunctionName(Operation operation)
{
    switch (operation) {
        case NONE: return "no-op";
        case TRANSMIT_FRAME: return "transmitFrame()";
        case EXPECT_FULL_REPLY: return "expectFullReplyWithin()";
        case EXPECT_REPLY_RXSTART: return "expectReplyStartTxWithin()";
        case GOTO_STEP: return "gotoStep()";
        case FAIL: return "fail()";
        case SUCCEED: return "succeed()";
        default: ASSERT(false); return "???";
    }
}

void StepBasedFrameExchange::startFrameExchange()
{
    EV_DETAIL << "Starting frame exchange " << getClassName() << std::endl;
    ASSERT(step == 0);
    operation = GOTO_STEP;
    gotoTarget = 0;
    proceed();
}

void StepBasedFrameExchange::proceed()
{
    if (status == INPROGRESS) {
        if (operation == GOTO_STEP)
            step = gotoTarget;
        else
            step++;
        EV_DETAIL << "Doing step " << step << "\n";
        operation = NONE;
        doStep(step);
        if (status == INPROGRESS) {
            logStatus("doStep()");
            if (operation == NONE)
                throw cRuntimeError(this, "doStep(step=%d) should have executed an operation like startContention(), transmitFrame(), expectFullReplyWithin(), expectReplyRxStartWithin(), gotoStep(), fail(), or succeed()", step);
            if (operation == GOTO_STEP)
                proceed();
        }
    }
    else
        throw cRuntimeError("Frame exchange finished");
}

FrameExchangeState StepBasedFrameExchange::lowerFrameReceived(Ieee80211Frame *frame)
{
    EV_DETAIL << "Lower frame received in step " << step << "\n";
    ASSERT(status == INPROGRESS);

    if (operation == EXPECT_FULL_REPLY) {
        operation = NONE;
        FrameExchangeState frameExchangeState = processReply(step, frame);
        if (status == INPROGRESS) {
            logStatus(frameExchangeState.result == FrameExchangeState::IGNORED ? "processReply(): frame IGNORED": "processReply(): frame PROCESSED");
            checkOperation(operation, "processReply()");
            if (frameExchangeState.result == FrameExchangeState::ACCEPTED || operation != NONE) {
                cancelEvent(timeoutMsg);
                proceed();
                if (isFinished()) {
                    frameExchangeState.result = FrameExchangeState::FINISHED;
                    return frameExchangeState;
                }
            }
            else
                operation = EXPECT_FULL_REPLY; // restore
        }
        return frameExchangeState;
    }
    else if (operation == EXPECT_REPLY_RXSTART) {
        operation = NONE;
        FrameExchangeState frameExchangeState = processReply(step, frame);
        if (status == INPROGRESS) {
            logStatus(frameExchangeState.result == FrameExchangeState::IGNORED ? "processReply(): frame IGNORED": "processReply(): frame PROCESSED");
            checkOperation(operation, "processReply()");
            if (frameExchangeState.result == FrameExchangeState::ACCEPTED || operation != NONE) {
                cancelEvent(timeoutMsg);
                proceed();
                if (isFinished()) {
                    frameExchangeState.result = FrameExchangeState::FINISHED;
                    return frameExchangeState;
                }
            }
            else {
                if (timeoutMsg->isScheduled())
                    operation = EXPECT_REPLY_RXSTART; // restore operation and continue waiting
                else
                    return handleTimeout();  // frame being received when timeout expired was not accepted as response: declare timeout
            }
        }
        return frameExchangeState;
    }
    else {
        return FrameExchangeState::DONT_CARE; // momentarily not interested in received frames
    }
}

void StepBasedFrameExchange::corruptedOrNotForUsFrameReceived()
{
    if (operation == EXPECT_REPLY_RXSTART && !timeoutMsg->isScheduled())
        handleTimeout();  // the frame we were receiving when the timeout expired was received incorrectly
}

FrameExchangeState StepBasedFrameExchange::handleSelfMessage(cMessage* msg)
{
    EV_DETAIL << "Timeout in step " << step << "\n";
    ASSERT(status == INPROGRESS);
    ASSERT(msg == timeoutMsg);
    if (operation == EXPECT_FULL_REPLY) {
        return handleTimeout();
    }
    else if (operation == EXPECT_REPLY_RXSTART) {
        // If there's no sign of the reply (e.g ACK) being received, declare timeout.
        // Otherwise we'll wait for the frame to be fully received and be reported
        // to us via lowerFrameReceived() or corruptedFrameReceived(), and decide then.
        if (!rx->isReceptionInProgress())
            return handleTimeout();
        return FrameExchangeState::DONT_CARE;
    }
    else {
        ASSERT(false);
    }
    return FrameExchangeState::DONT_CARE;
}


void StepBasedFrameExchange::checkOperation(Operation operation, const char *where)
{
    switch (operation) {
        case NONE: case GOTO_STEP: break;
        case FAIL: case SUCCEED: ASSERT(false); break;  // it is not safe to do anything after fail() or succeed(), as the callback may delete this object
        default: throw cRuntimeError(this, "operation %s is not permitted inside %s, only gotoStep(), fail() and succeed())", where, operationFunctionName(operation));
    }
}

FrameExchangeState StepBasedFrameExchange::handleTimeout()
{
    operation = NONE;
    FrameExchangeState state = processTimeout(step);
    if (status == INPROGRESS) {
        logStatus("processTimeout()");
        checkOperation(operation, "processTimeout()");
    }
    return state;
}

void StepBasedFrameExchange::continueFrameExchange()
{
    EV_DETAIL << "Continuing frame exchange " << getClassName() << std::endl;
    proceed();
}


void StepBasedFrameExchange::abortFrameExchange()
{
    EV_DETAIL << "Aborting frame exchange " << getClassName() << std::endl;
}

void StepBasedFrameExchange::transmitFrame(Ieee80211Frame *frame)
{
    setOperation(TRANSMIT_FRAME);
    tx->transmitFrame(frame);
}

void StepBasedFrameExchange::transmitFrame(Ieee80211Frame *frame, simtime_t ifs)
{
    setOperation(TRANSMIT_FRAME);
    tx->transmitFrame(frame, ifs);
}

void StepBasedFrameExchange::succeed()
{
    EV_DETAIL << "Frame exchange successful\n";
    setOperation(SUCCEED);
    status = SUCCEEDED;
    finished = true;
}

void StepBasedFrameExchange::expectFullReplyWithin(simtime_t timeout)
{
    setOperation(EXPECT_FULL_REPLY);
    if (!timeoutMsg)
        timeoutMsg = new cMessage("timeout");
    scheduleAt(simTime() + timeout, timeoutMsg);
}

void StepBasedFrameExchange::expectReplyRxStartWithin(simtime_t timeout)
{
    setOperation(EXPECT_REPLY_RXSTART);
    if (!timeoutMsg)
        timeoutMsg = new cMessage("timeout");
    scheduleAt(simTime() + timeout, timeoutMsg);
}

void StepBasedFrameExchange::gotoStep(int step)
{
    setOperation(GOTO_STEP);
    gotoTarget = step;
}

void StepBasedFrameExchange::setOperation(Operation newOperation)
{
    if (status != INPROGRESS)
        throw cRuntimeError(this, "cannot do operation %s: frame exchange already terminated (%s)", operationFunctionName(newOperation), statusName(status));
    if (operation != NONE && operation != GOTO_STEP)
        throw cRuntimeError(this, "only one operation is permitted per step: cannot do %s after %s, in doStep(step=%d)", operationFunctionName(newOperation), operationFunctionName(operation), step);
    operation = newOperation;
}

void StepBasedFrameExchange::logStatus(const char *what)
{
    if (status != INPROGRESS)
        EV_DETAIL << what << " in step=" << step << " terminated the frame exchange: " << statusName(status) << endl;
    else
        EV_DETAIL << what << " in step=" << step << " performed " << operationFunctionName(operation) << endl;
}

void StepBasedFrameExchange::cleanup()
{
    if (timeoutMsg)
        cancelEvent(timeoutMsg);
}


} // namespace ieee80211
} // namespace inet
