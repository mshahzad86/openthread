/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *  This file includes definitions for the Joiner Router role.
 */

#ifndef OT_CORE_MESHCOP_JOINER_ROUTER_HPP_
#define OT_CORE_MESHCOP_JOINER_ROUTER_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_FTD

#include "coap/coap_message.hpp"
#include "common/locator.hpp"
#include "common/message.hpp"
#include "common/non_copyable.hpp"
#include "common/notifier.hpp"
#include "common/timer.hpp"
#include "mac/mac_types.hpp"
#include "meshcop/meshcop_tlvs.hpp"
#include "net/udp6.hpp"
#include "thread/key_manager.hpp"
#include "thread/tmf.hpp"

namespace ot {

namespace MeshCoP {

class JoinerRouter : public InstanceLocator, private NonCopyable
{
    friend class ot::Notifier;
    friend class Tmf::Agent;

public:
    /**
     * Initializes the Joiner Router object.
     *
     * @param[in]  aInstance     A reference to the OpenThread instance.
     */
    explicit JoinerRouter(Instance &aInstance);

    /**
     * Returns the Joiner UDP Port.
     *
     * @returns The Joiner UDP Port number.
     */
    uint16_t GetJoinerUdpPort(void) const;

    /**
     * Sets the Joiner UDP Port.
     *
     * @param[in]  aJoinerUdpPort  The Joiner UDP Port number.
     */
    void SetJoinerUdpPort(uint16_t aJoinerUdpPort);

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    /**
     * Decides the PAN ID to advertise for the next commissioning attempt (Multi-PAN).
     *
     * Must be called once per Discovery Response, before it is built. The joiner keeps the PAN it learns from the
     * Discovery Response, so the decision made here is the PAN it ends up on.
     *
     * - If a Joiner DTLS session is in progress, the pending PAN is left untouched.
     * - Otherwise, if the Commissioner has an expected (most recently added, not yet finalized) EUI-64 Joiner, its
     *   pre-assigned PAN (group PAN or solo PAN) is used.
     * - Otherwise (wildcard / discerner joiners), a PAN is allocated from the round-robin pool. An unconsumed
     *   round-robin PAN is reused instead of burning a new one.
     *
     * @retval kErrorNone    A PAN is decided (or the PAN ID list is empty, so the router's own PAN is used).
     * @retval kErrorNoBufs  The PAN ID list is configured but the pool has no free PAN. The Discovery Response must
     *                       not be sent (fail closed, rather than putting the joiner on the router's own PAN).
     */
    Error SelectPanIdForDiscovery(void);

    /**
     * Returns the PAN ID decided for the current commissioning attempt (see `SelectPanIdForDiscovery()`).
     *
     * If none is pending, only a PAN pre-assigned to an expected joiner is picked up (a round-robin PAN is never
     * allocated here). Falls back to the router's own PAN ID if no PAN is available.
     *
     * @returns The PAN ID for the joiner being commissioned.
     */
    uint16_t GetOrAllocateNextPanId(void);

    /**
     * Returns the pending PAN ID without consuming it.
     *
     * @param[out] aPanId  The pending PAN ID (valid only when returning true).
     *
     * @retval TRUE   A PAN ID is pending.
     * @retval FALSE  No PAN ID is pending.
     */
    bool PeekPendingPanId(uint16_t &aPanId) const;

    /**
     * Gets and consumes (clears) the PAN ID allocated for the current commissioning attempt.
     *
     * Called when the joiner gets its Child ID Response, so the next commissioning round decides a new PAN.
     *
     * @param[out] aPanId  The allocated PAN ID (valid only when returning true).
     *
     * @retval TRUE   A pending PAN ID was returned in @p aPanId (and consumed).
     * @retval FALSE  No PAN ID was pending.
     */
    bool LookupPendingPanId(uint16_t &aPanId);
#endif

private:
    static constexpr uint16_t kDefaultJoinerUdpPort = OPENTHREAD_CONFIG_JOINER_UDP_PORT;
    static constexpr uint32_t kJoinerEntrustTxDelay = 50; // in msec

    struct JoinerEntrustMetadata : public Message::FooterData<JoinerEntrustMetadata>
    {
        Ip6::MessageInfo mMessageInfo; // Message info of the message to send.
        TimeMilli        mSendTime;    // Time when the message shall be sent.
        Kek              mKek;         // KEK used by MAC layer to encode this message.
    };

    void HandleNotifierEvents(Events aEvents);
#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    Error DecidePanId(bool aAllowRoundRobin);
#endif

    void HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo);

    template <Uri kUri> void HandleTmf(Coap::Msg &aMsg);

    DeclareTmfResponseHandlerIn(JoinerRouter, HandleJoinerEntrustResponse);

    void HandleTimer(void);

    void           Start(void);
    void           DelaySendingJoinerEntrust(const Ip6::MessageInfo &aMessageInfo, const Kek &aKek);
    void           SendDelayedJoinerEntrust(void);
    Error          SendJoinerEntrust(const JoinerEntrustMetadata &aMetadata);
    Coap::Message *PrepareJoinerEntrustMessage(void);

    using JoinerRouterTimer = TimerMilliIn<JoinerRouter, &JoinerRouter::HandleTimer>;
    using JoinerSocket      = Ip6::Udp::SocketIn<JoinerRouter, &JoinerRouter::HandleUdpReceive>;

    JoinerSocket mSocket;

    JoinerRouterTimer mTimer;
    MessageQueue      mDelayedJoinEnts;

    uint16_t mJoinerUdpPort;

    bool mIsJoinerPortConfigured : 1;

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    enum PendingOrigin : uint8_t
    {
        kPendingNone,           // No PAN pending.
        kPendingExpectedJoiner, // PAN pre-assigned to the Commissioner's expected Joiner entry.
        kPendingRoundRobin,     // PAN allocated from the round-robin pool (wildcard/discerner joiners).
    };

    bool          mHasPendingPanId;
    PendingOrigin mPendingOrigin;
    uint16_t      mPendingPanId;
#endif
};

DeclareTmfHandler(JoinerRouter, kUriRelayTx);

} // namespace MeshCoP
} // namespace ot

#endif // OPENTHREAD_FTD

#endif // OT_CORE_MESHCOP_JOINER_ROUTER_HPP_
