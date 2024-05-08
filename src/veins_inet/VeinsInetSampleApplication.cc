//
// Copyright (C) 2018 Christoph Sommer <sommer@ccs-labs.org>
//
// Documentation for these modules is at http://veins.car2x.org/
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#include "veins_inet/VeinsInetSampleApplication.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

#include "veins_inet/VeinsInetSampleMessage_m.h"

using namespace inet;

Define_Module(VeinsInetSampleApplication);

VeinsInetSampleApplication::VeinsInetSampleApplication() {
}

bool VeinsInetSampleApplication::startApplication() {

    // host[0] should stop at t=20s
    auto callback = [this]() {

        if (getParentModule()->getIndex() == 0) {
            getParentModule()->getDisplayString().setTagArg("i", 1, "red");
            traciVehicle->setSpeed(0);
            auto payload = makeShared<VeinsInetSampleMessage>();
            payload->setChunkLength(B(100));
            payload->setRoadId(traciVehicle->getRoadId().c_str());
            timestampPayload(payload);

            auto packet = createPacket("accident");
            packet->insertAtBack(payload);
            sendPacket(std::move(packet));
        }

        // host should continue after 30s
        auto callback = [this]() {
            traciVehicle->setSpeed(-1);
        };
        timerManager.create(
                veins::TimerSpecification(callback).oneshotIn(
                        SimTime(30, SIMTIME_S)));
    };
    timerManager.create(
            veins::TimerSpecification(callback).oneshotAt(
                    SimTime(20, SIMTIME_S)));

    //schedule when car 1 stops if there is a malicious node
    auto callback10 = [this]() {

        if (getParentModule()->getIndex() == 1
                && (par("isMalicious").boolValue())) {
            getParentModule()->getDisplayString().setTagArg("i", 1, "yellow");
            traciVehicle->setSpeed(0);
        }

        // car1 should continue after 30s
        auto callback11 = [this]() {
            traciVehicle->setSpeed(-1);
        };
        timerManager.create(
                veins::TimerSpecification(callback11).oneshotIn(
                        SimTime(30, SIMTIME_S)));
    };
    timerManager.create(
            veins::TimerSpecification(callback10).oneshotAt(
                    SimTime(25, SIMTIME_S)));

    //schedule when car 2 stops if there is a malicious node
    auto callback20 = [this]() {

        if (getParentModule()->getIndex() == 2
                && (par("isMalicious").boolValue())) {
            traciVehicle->setSpeed(0);
        }

        // car1 should continue after 30s
        auto callback21 = [this]() {
            traciVehicle->setSpeed(-1);
        };
        timerManager.create(
                veins::TimerSpecification(callback21).oneshotIn(
                        SimTime(33, SIMTIME_S)));
    };
    timerManager.create(
            veins::TimerSpecification(callback20).oneshotAt(
                    SimTime(30, SIMTIME_S)));

    return true;
}

bool VeinsInetSampleApplication::stopApplication() {
    return true;
}

VeinsInetSampleApplication::~VeinsInetSampleApplication() {
}

void VeinsInetSampleApplication::processPacket(
        std::shared_ptr<inet::Packet> pk) {
    auto payload = pk->peekAtFront<VeinsInetSampleMessage>();
    EV << "Processing packet: Attacker Mode set to: "
              << par("isMalicious").boolValue() << endl;

    // Check if the hasAttacker parameter is true
    if (par("isMalicious").boolValue()) {
        EV << "Malicious car found" << getIndex()
                  << " intercepting messages and dropping them" << endl;
        return; // Discard all intercepted packets, do not forward or process
    }

    EV_INFO << "Received packet: " << payload << endl;

    getParentModule()->getDisplayString().setTagArg("i", 1, "green");

    traciVehicle->changeRoute(payload->getRoadId(), 999.9);

    if (haveForwarded)
        return;

    auto packet = createPacket("relay");
    packet->insertAtBack(payload);
    sendPacket(std::move(packet));

    haveForwarded = true;
}
