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
 *   This file implements the Joiner Router role.
 */

#include "joiner_router.hpp"

#if OPENTHREAD_FTD

#include "instance/instance.hpp"
#include "thread/device_assignment.hpp"

namespace ot {
namespace MeshCoP {

RegisterLogModule("JoinerRouter");

JoinerRouter::JoinerRouter(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mSocket(aInstance, *this)
    , mTimer(aInstance)
    , mJoinerUdpPort(0)
    , mIsJoinerPortConfigured(false)
#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    , mHasPendingPanId(false)
    , mPendingOrigin(kPendingNone)
    , mPendingPanId(0)
#endif
{
}

void JoinerRouter::HandleNotifierEvents(Events aEvents)
{
    if (aEvents.Contains(kEventThreadNetdataChanged))
    {
        Start();
    }
}

void JoinerRouter::Start(void)
{
    VerifyOrExit(Get<Mle::Mle>().IsFullThreadDevice());

    if (Get<NetworkData::Leader>().IsJoiningAllowed())
    {
        uint16_t port = GetJoinerUdpPort();

        VerifyOrExit(!mSocket.IsBound());

        IgnoreError(mSocket.Open(Ip6::kNetifThreadInternal));
        IgnoreError(mSocket.Bind(port));
        IgnoreError(Get<Ip6::Filter>().AddUnsecurePort(port));
        LogInfo("Joiner Router: start");
    }
    else
    {
        VerifyOrExit(mSocket.IsBound());

        IgnoreError(Get<Ip6::Filter>().RemoveUnsecurePort(mSocket.GetSockName().mPort));

        IgnoreError(mSocket.Close());
    }

exit:
    return;
}

uint16_t JoinerRouter::GetJoinerUdpPort(void) const
{
    uint16_t port;

    if (mIsJoinerPortConfigured)
    {
        ExitNow(port = mJoinerUdpPort);
    }

    if (Get<NetworkData::Leader>().FindJoinerUdpPort(port) == kErrorNone)
    {
        ExitNow();
    }

    port = kDefaultJoinerUdpPort;

exit:
    return port;
}

void JoinerRouter::SetJoinerUdpPort(uint16_t aJoinerUdpPort)
{
    mJoinerUdpPort          = aJoinerUdpPort;
    mIsJoinerPortConfigured = true;
    Start();
}

void JoinerRouter::HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    Error          error;
    Coap::Message *message = nullptr;
    uint16_t       borderAgentRloc;
    OffsetRange    offsetRange;

    LogInfo("JoinerRouter::HandleUdpReceive");

    SuccessOrExit(error = Get<NetworkData::Leader>().FindBorderAgentRloc(borderAgentRloc));

    message = Get<Tmf::Agent>().AllocateAndInitPriorityNonConfirmablePostMessage(kUriRelayRx);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    SuccessOrExit(error = Tlv::Append<JoinerUdpPortTlv>(*message, aMessageInfo.GetPeerPort()));
    SuccessOrExit(error = Tlv::Append<JoinerIidTlv>(*message, aMessageInfo.GetPeerAddr().GetIid()));
    SuccessOrExit(error = Tlv::Append<JoinerRouterLocatorTlv>(*message, Get<Mle::Mle>().GetRloc16()));

    offsetRange.InitFromMessageOffsetToEnd(aMessage);
    SuccessOrExit(
        error = Tlv::AppendTlvWithValueFromMessage(*message, Tlv::kJoinerDtlsEncapsulation, aMessage, offsetRange));

    SuccessOrExit(error = Get<Tmf::Agent>().SendMessageToRloc(*message, borderAgentRloc));

    LogInfo("Sent %s", UriToString<kUriRelayRx>());

exit:
    FreeMessageOnError(message, error);
}

template <> void JoinerRouter::HandleTmf<kUriRelayTx>(Coap::Msg &aMsg)
{
    Error                    error;
    uint16_t                 joinerPort;
    Ip6::InterfaceIdentifier joinerIid;
    Kek                      kek;
    OffsetRange              offsetRange;
    Message                 *message = nullptr;
    Message::Settings        settings(kNoLinkSecurity, Message::kPriorityNet);
    Ip6::MessageInfo         messageInfo;

    VerifyOrExit(aMsg.IsNonConfirmable(), error = kErrorDrop);

    LogInfo("Received %s", UriToString<kUriRelayTx>());

    SuccessOrExit(error = Tlv::Find<JoinerUdpPortTlv>(aMsg.mMessage, joinerPort));
    SuccessOrExit(error = Tlv::Find<JoinerIidTlv>(aMsg.mMessage, joinerIid));

    SuccessOrExit(error = Tlv::FindTlvValueOffsetRange(aMsg.mMessage, Tlv::kJoinerDtlsEncapsulation, offsetRange));

    VerifyOrExit((message = mSocket.NewMessage(settings)) != nullptr, error = kErrorNoBufs);

    SuccessOrExit(error = message->AppendBytesFromMessage(aMsg.mMessage, offsetRange));

    messageInfo.GetPeerAddr().InitAsLinkLocalAddress(joinerIid);
    messageInfo.SetPeerPort(joinerPort);

    SuccessOrExit(error = mSocket.SendTo(*message, messageInfo));

    if (Tlv::Find<JoinerRouterKekTlv>(aMsg.mMessage, kek) == kErrorNone)
    {
        LogInfo("Received kek");

        DelaySendingJoinerEntrust(messageInfo, kek);
    }

exit:
    FreeMessageOnError(message, error);
}

void JoinerRouter::DelaySendingJoinerEntrust(const Ip6::MessageInfo &aMessageInfo, const Kek &aKek)
{
    Error                 error   = kErrorNone;
    Message              *message = Get<MessagePool>().Allocate(Message::kTypeOther);
    JoinerEntrustMetadata metadata;

    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    metadata.mMessageInfo = aMessageInfo;
    metadata.mMessageInfo.SetPeerPort(Tmf::kUdpPort);
    metadata.mSendTime = TimerMilli::GetNow() + kJoinerEntrustTxDelay;
    metadata.mKek      = aKek;

    SuccessOrExit(error = metadata.AppendTo(*message));

    mDelayedJoinEnts.Enqueue(*message);

    if (!mTimer.IsRunning())
    {
        mTimer.FireAt(metadata.mSendTime);
    }

exit:
    FreeMessageOnError(message, error);
    LogWarnOnError(error, "schedule joiner entrust");
}

void JoinerRouter::HandleTimer(void) { SendDelayedJoinerEntrust(); }

void JoinerRouter::SendDelayedJoinerEntrust(void)
{
    JoinerEntrustMetadata metadata;
    Message              *message = mDelayedJoinEnts.GetHead();

    VerifyOrExit(message != nullptr);
    VerifyOrExit(!mTimer.IsRunning());

    metadata.ReadFrom(*message);

    if (TimerMilli::GetNow() < metadata.mSendTime)
    {
        mTimer.FireAt(metadata.mSendTime);
    }
    else
    {
        mDelayedJoinEnts.DequeueAndFree(*message);

        if (SendJoinerEntrust(metadata) != kErrorNone)
        {
            mTimer.Start(0);
        }
    }

exit:
    return;
}

Error JoinerRouter::SendJoinerEntrust(const JoinerEntrustMetadata &aMetadata)
{
    Error          error   = kErrorNone;
    Coap::Message *message = nullptr;

    IgnoreError(Get<Tmf::Agent>().AbortTransaction(HandleJoinerEntrustResponse, this));

    message = PrepareJoinerEntrustMessage();
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    Get<KeyManager>().SetKek(aMetadata.mKek);

    SuccessOrExit(
        error = Get<Tmf::Agent>().SendMessage(*message, aMetadata.mMessageInfo, HandleJoinerEntrustResponse, this));

    LogInfo("Sent %s (len= %d)", UriToString<kUriJoinerEntrust>(), message->GetLength());
    LogCert("[THCI] direction=send | type=JOIN_ENT.ntf");

exit:
    if (error != kErrorNone)
    {
        Get<KeyManager>().ClearKek();
        FreeMessage(message);
    }

    return error;
}

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE

Error JoinerRouter::SelectPanIdForDiscovery(void) { return DecidePanId(/* aAllowRoundRobin */ true); }

Error JoinerRouter::DecidePanId(bool aAllowRoundRobin)
{
    Error error   = kErrorNone;
    bool  decided = false;

#if OPENTHREAD_CONFIG_COMMISSIONER_ENABLE
    Commissioner &commissioner = Get<Commissioner>();

    if (commissioner.IsJoinerSessionActive())
    {
        // Another Joiner is mid-commissioning. Its PAN must not change
        // under it, so keep the pending PAN as is. (Concurrent
        // onboarding on different PANs is not supported: a second
        // joiner discovered now would be told the same PAN.)
        decided = true;
        LogMultiPan("SelectPanIdForDiscovery: session in progress, keep pending=%u 0x%04x", mHasPendingPanId,
                    mPendingPanId);
    }
    else
    {
        // The Discovery Request carries no joiner identity, so the
        // best the router can do is to advertise the PAN pre-assigned
        // (at `commissioner joiner add` time) to the joiner the
        // operator added most recently that has not finished
        // commissioning yet.
        uint16_t expectedPanId = commissioner.GetExpectedJoinerPanId();

        if (expectedPanId != Commissioner::kNoAssignedPanId)
        {
            mPendingPanId    = expectedPanId;
            mHasPendingPanId = true;
            mPendingOrigin   = kPendingExpectedJoiner;
            decided          = true;
            LogMultiPan("SelectPanIdForDiscovery: expected joiner -> PAN 0x%04x", expectedPanId);
        }
    }
#endif // OPENTHREAD_CONFIG_COMMISSIONER_ENABLE

    // Wildcard / discerner joiners have no pre-assigned PAN: allocate
    // one from the round-robin pool. An unconsumed round-robin PAN is
    // reused so repeated discoveries do not burn PANs.
    if (aAllowRoundRobin && !decided && (!mHasPendingPanId || (mPendingOrigin == kPendingExpectedJoiner)))
    {
        const PanIdAssignment *assignment;

#if OPENTHREAD_CONFIG_COMMISSIONER_ENABLE
        assignment = Get<Commissioner>().AllocatePanId();
#else
        assignment = Get<KeyManager>().AllocateNextPanId();
#endif

        if (assignment != nullptr)
        {
            mPendingPanId    = assignment->mPanId;
            mHasPendingPanId = true;
            mPendingOrigin   = kPendingRoundRobin;
            LogMultiPan("Pre-allocated PAN 0x%04x from pool for next joiner", assignment->mPanId);
        }
        else
        {
            mHasPendingPanId = false;
            mPendingOrigin   = kPendingNone;

            // Fail closed when Multi-PAN is in use: the joiner is not
            // silently put on the router's own PAN.
            if (Get<KeyManager>().GetPanIdCount() > 0)
            {
                error = kErrorNoBufs;
                LogWarn("PAN pool exhausted, no PAN for the next joiner");
            }
        }
    }

    return error;
}

uint16_t JoinerRouter::GetOrAllocateNextPanId(void)
{
    if (!mHasPendingPanId)
    {
        // Not a Discovery Response: only pick up a PAN pre-assigned to
        // an expected joiner, never burn a round-robin PAN for a frame
        // that happens to be addressed to an unknown device.
        IgnoreError(DecidePanId(/* aAllowRoundRobin */ false));
    }

    return mHasPendingPanId ? mPendingPanId : Get<Mac::Mac>().GetPanId();
}

bool JoinerRouter::PeekPendingPanId(uint16_t &aPanId) const
{
    if (mHasPendingPanId)
    {
        aPanId = mPendingPanId;
    }

    return mHasPendingPanId;
}

bool JoinerRouter::LookupPendingPanId(uint16_t &aPanId)
{
    bool found = false;

    LogMultiPan("LookupPendingPanId: hasPending=%u pending=0x%04x", mHasPendingPanId, mPendingPanId);

    VerifyOrExit(mHasPendingPanId);

    aPanId           = mPendingPanId;
    mHasPendingPanId = false;
    mPendingOrigin   = kPendingNone;
    found            = true;

exit:
    return found;
}

#endif // OPENTHREAD_CONFIG_MULTI_PAN_ENABLE

Coap::Message *JoinerRouter::PrepareJoinerEntrustMessage(void)
{
    static const Tlv::Type kTlvTypes[] = {
        Tlv::kNetworkKey,      Tlv::kMeshLocalPrefix, Tlv::kExtendedPanId, Tlv::kNetworkName,
        Tlv::kActiveTimestamp, Tlv::kChannelMask,     Tlv::kPskc,          Tlv::kSecurityPolicy,
    };

    Error          error   = kErrorNone;
    Coap::Message *message = nullptr;
    Dataset        dataset;

    message = Get<Tmf::Agent>().AllocateAndInitPriorityConfirmablePostMessage(kUriJoinerEntrust);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    message->SetSubType(Message::kSubTypeJoinerEntrust);

    SuccessOrExit(error = Get<ActiveDatasetManager>().Read(dataset));

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    {
        // Multi-PAN: entrust the joiner with the Network Key of the PAN
        // it was told in the Discovery Response. This only reads the
        // pending PAN, so an aborted and retried entrust neither
        // consumes nor leaks it.

        KeyManager            &keyManager = Get<KeyManager>();
        uint16_t               panId      = GetOrAllocateNextPanId();
        const PanIdAssignment *assignment;

        assignment = FindPanIdAssignment(keyManager.GetPanIdPool(), keyManager.GetPanIdPoolSize(), panId);

        if (assignment != nullptr)
        {
            NetworkKey networkKey;

            memcpy(networkKey.m8, assignment->mNetworkKey, NetworkKey::kSize);
            SuccessOrExit(error = dataset.Write<NetworkKeyTlv>(networkKey));
            LogMultiPan("Entrust: using PAN 0x%04x / NetworkKey for joiner", assignment->mPanId);
        }
    }
#endif

    for (Tlv::Type tlvType : kTlvTypes)
    {
        const Tlv *tlv = dataset.FindTlv(tlvType);

        VerifyOrExit(tlv != nullptr, error = kErrorInvalidState);
        SuccessOrExit(error = tlv->AppendTo(*message));
    }

    SuccessOrExit(error = Tlv::Append<NetworkKeySequenceTlv>(*message, Get<KeyManager>().GetCurrentKeySequence()));

exit:
    FreeAndNullMessageOnError(message, error);
    return message;
}

void JoinerRouter::HandleJoinerEntrustResponse(Coap::Msg *aMsg, Error aResult)
{
    Get<KeyManager>().ClearKek();

    VerifyOrExit(aResult != kErrorAbort);

    SendDelayedJoinerEntrust();

    VerifyOrExit(aResult == kErrorNone && aMsg != nullptr);

    VerifyOrExit(aMsg->GetCode() == Coap::kCodeChanged);

    LogInfo("Receive %s response", UriToString<kUriJoinerEntrust>());
    LogCert("[THCI] direction=recv | type=JOIN_ENT.rsp");

exit:
    return;
}

} // namespace MeshCoP
} // namespace ot

#endif // OPENTHREAD_FTD
