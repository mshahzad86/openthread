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
 *   This file implements a Commissioner role.
 */

#include "commissioner.hpp"

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_COMMISSIONER_ENABLE

#include "instance/instance.hpp"
#include "thread/device_assignment.hpp"

namespace ot {
namespace MeshCoP {

RegisterLogModule("Commissioner");

Commissioner::Commissioner(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mActiveJoiner(nullptr)
    , mJoinerPort(0)
    , mJoinerRloc(0)
    , mSessionId(0)
    , mTransmitAttempts(0)
    , mState(kStateDisabled)
    , mJoinerExpirationTimer(aInstance)
    , mTimer(aInstance)
    , mJoinerSessionTimer(aInstance)
{
    ClearAllBytes(mJoiners);
#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    ClearAllBytes(mGroupRegistry);
    mAddSequenceCounter = 0;
#endif

    mCommissionerAloc.InitAsThreadOriginMeshLocal();
    mCommissionerAloc.mPreferred = true;

    IgnoreError(SetId("OpenThread Commissioner"));

    mProvisioningUrl[0] = kNullChar;
}

void Commissioner::SetState(State aState)
{
    State oldState = mState;

    OT_UNUSED_VARIABLE(oldState);

    SuccessOrExit(Get<Notifier>().Update(mState, aState, kEventCommissionerStateChanged));

    LogInfo("State: %s -> %s", StateToString(oldState), StateToString(aState));

    mStateCallback.InvokeIfSet(MapEnum(mState));

exit:
    return;
}

void Commissioner::SignalJoinerEvent(JoinerEvent aEvent, const Joiner *aJoiner) const
{
    otJoinerInfo    joinerInfo;
    Mac::ExtAddress joinerId;
    bool            noJoinerId = false;

    VerifyOrExit(mJoinerCallback.IsSet() && (aJoiner != nullptr));

    aJoiner->CopyToJoinerInfo(joinerInfo);

    if (aJoiner->mType == Joiner::kTypeEui64)
    {
        ComputeJoinerId(aJoiner->mSharedId.mEui64, joinerId);
    }
    else if (aJoiner == mActiveJoiner)
    {
        joinerId.SetFromIid(mJoinerIid);
    }
    else
    {
        noJoinerId = true;
    }

    mJoinerCallback.Invoke(MapEnum(aEvent), &joinerInfo, noJoinerId ? nullptr : &joinerId);

exit:
    return;
}

void Commissioner::HandleSecureAgentConnectEvent(Dtls::Session::ConnectEvent aEvent, void *aContext)
{
    static_cast<Commissioner *>(aContext)->HandleSecureAgentConnectEvent(aEvent);
}

void Commissioner::HandleSecureAgentConnectEvent(Dtls::Session::ConnectEvent aEvent)
{
    bool isConnected = (aEvent == Dtls::Session::kConnected);
    if (!isConnected)
    {
        mJoinerSessionTimer.Stop();
    }

    SignalJoinerEvent(isConnected ? kJoinerEventConnected : kJoinerEventEnd, mActiveJoiner);

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    if (!isConnected)
    {
        // The session is over (finished, failed or timed out). Nothing about the *next* joiner
        // may be decided from this one, so don't leave a stale pointer behind.
        mActiveJoiner = nullptr;
    }
#endif
}

Commissioner::Joiner *Commissioner::GetUnusedJoinerEntry(void)
{
    Joiner *rval = nullptr;

    for (Joiner &joiner : mJoiners)
    {
        if (joiner.mType == Joiner::kTypeUnused)
        {
            rval = &joiner;
            break;
        }
    }

    return rval;
}

Commissioner::Joiner *Commissioner::FindJoinerEntry(const Mac::ExtAddress *aEui64)
{
    Joiner *rval = nullptr;

    for (Joiner &joiner : mJoiners)
    {
        switch (joiner.mType)
        {
        case Joiner::kTypeUnused:
        case Joiner::kTypeDiscerner:
            break;

        case Joiner::kTypeAny:
            if (aEui64 == nullptr)
            {
                ExitNow(rval = &joiner);
            }
            break;

        case Joiner::kTypeEui64:
            if ((aEui64 != nullptr) && (joiner.mSharedId.mEui64 == *aEui64))
            {
                ExitNow(rval = &joiner);
            }
            break;
        }
    }

exit:
    return rval;
}

Commissioner::Joiner *Commissioner::FindJoinerEntry(const JoinerDiscerner &aDiscerner)
{
    Joiner *rval = nullptr;

    for (Joiner &joiner : mJoiners)
    {
        if ((joiner.mType == Joiner::kTypeDiscerner) && (aDiscerner == joiner.mSharedId.mDiscerner))
        {
            rval = &joiner;
            break;
        }
    }

    return rval;
}

Commissioner::Joiner *Commissioner::FindBestMatchingJoinerEntry(const Mac::ExtAddress &aReceivedJoinerId)
{
    Joiner         *best = nullptr;
    Mac::ExtAddress joinerId;

    // Prefer a full Joiner ID match, if not found use the entry
    // accepting any joiner.

    for (Joiner &joiner : mJoiners)
    {
        switch (joiner.mType)
        {
        case Joiner::kTypeUnused:
            break;

        case Joiner::kTypeAny:
            if (best == nullptr)
            {
                best = &joiner;
            }
            break;

        case Joiner::kTypeEui64:
            ComputeJoinerId(joiner.mSharedId.mEui64, joinerId);
            if (joinerId == aReceivedJoinerId)
            {
                ExitNow(best = &joiner);
            }
            break;

        case Joiner::kTypeDiscerner:
            if (joiner.mSharedId.mDiscerner.Matches(aReceivedJoinerId))
            {
                if ((best == nullptr) ||
                    ((best->mType == Joiner::kTypeDiscerner) &&
                     (best->mSharedId.mDiscerner.GetLength() < joiner.mSharedId.mDiscerner.GetLength())))
                {
                    best = &joiner;
                }
            }
            break;
        }
    }

exit:
    return best;
}

void Commissioner::RemoveJoinerEntry(Commissioner::Joiner &aJoiner)
{
    // Create a copy of `aJoiner` to use for signaling joiner event
    // and logging after the entry is removed. This ensures the joiner
    // event callback is invoked after all states are cleared.

    Joiner joinerCopy = aJoiner;

    aJoiner.mType = Joiner::kTypeUnused;

    if (&aJoiner == mActiveJoiner)
    {
#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
        LogMultiPan("mActiveJoiner cleared (joiner entry removed)");
#endif
        mActiveJoiner = nullptr;
    }

    SendCommissionerSet();

    LogJoinerEntry("Removed", joinerCopy);
    SignalJoinerEvent(kJoinerEventRemoved, &joinerCopy);
}

Error Commissioner::Start(StateCallback aStateCallback, JoinerCallback aJoinerCallback, void *aCallbackContext)
{
    Error error = kErrorNone;

    VerifyOrExit(Get<Mle::Mle>().IsAttached(), error = kErrorInvalidState);
    VerifyOrExit(mState == kStateDisabled, error = kErrorAlready);

    SuccessOrExit(error = Get<Tmf::SecureAgent>().Open(SendRelayTransmit, this));

    Get<Tmf::SecureAgent>().SetConnectCallback(HandleSecureAgentConnectEvent, this);

    mStateCallback.Set(aStateCallback, aCallbackContext);
    mJoinerCallback.Set(aJoinerCallback, aCallbackContext);
    mTransmitAttempts = 0;

    SuccessOrExit(error = SendPetition());
    SetState(kStatePetition);

    LogInfo("start commissioner %s", mCommissionerId);

exit:
    if ((error != kErrorNone) && (error != kErrorAlready))
    {
        Get<Tmf::SecureAgent>().Close();
        LogWarnOnError(error, "start commissioner");
    }

    return error;
}

Error Commissioner::Stop(ResignMode aResignMode)
{
    Error error      = kErrorNone;
    bool  needResign = false;

    VerifyOrExit(mState != kStateDisabled, error = kErrorAlready);

    mJoinerSessionTimer.Stop();
    Get<Tmf::SecureAgent>().Close();

    if (mState == kStateActive)
    {
        Get<ThreadNetif>().RemoveUnicastAddress(mCommissionerAloc);
        ClearJoiners();
        needResign = true;
    }
    else if (mState == kStatePetition)
    {
        mTransmitAttempts = 0;
    }

    mTimer.Stop();

    SetState(kStateDisabled);

    if (needResign && (aResignMode == kSendKeepAliveToResign))
    {
        SendKeepAlive();
    }

exit:
    if (error != kErrorAlready)
    {
        LogWarnOnError(error, "stop commissioner");
    }

    return error;
}

Error Commissioner::SetId(const char *aId)
{
    Error error = kErrorNone;

    VerifyOrExit(IsDisabled(), error = kErrorInvalidState);
    error = StringCopy(mCommissionerId, aId, kStringCheckUtf8Encoding);

exit:
    return error;
}

void Commissioner::ComputeBloomFilter(SteeringData &aSteeringData) const
{
    Mac::ExtAddress joinerId;

    IgnoreError(aSteeringData.Init(SteeringData::kMaxLength));

    for (const Joiner &joiner : mJoiners)
    {
        switch (joiner.mType)
        {
        case Joiner::kTypeUnused:
            break;

        case Joiner::kTypeEui64:
            ComputeJoinerId(joiner.mSharedId.mEui64, joinerId);
            IgnoreError(aSteeringData.UpdateBloomFilter(joinerId));
            break;

        case Joiner::kTypeDiscerner:
            IgnoreError(aSteeringData.UpdateBloomFilter(joiner.mSharedId.mDiscerner));
            break;

        case Joiner::kTypeAny:
            aSteeringData.SetToPermitAllJoiners();
            ExitNow();
        }
    }

exit:
    return;
}

void Commissioner::SendCommissionerSet(void)
{
    Error                error = kErrorNone;
    CommissioningDataset dataset;

    VerifyOrExit(mState == kStateActive, error = kErrorInvalidState);

    dataset.Clear();

    dataset.SetSessionId(mSessionId);
    ComputeBloomFilter(dataset.UpdateSteeringData());

    error = SendMgmtCommissionerSetRequest(dataset, nullptr, 0);

exit:
    LogWarnOnError(error, "send MGMT_COMMISSIONER_SET.req");
    OT_UNUSED_VARIABLE(error);
}

void Commissioner::ClearJoiners(void)
{
    for (Joiner &joiner : mJoiners)
    {
        joiner.mType = Joiner::kTypeUnused;
    }

    SendCommissionerSet();
}

Error Commissioner::AddJoiner(const Mac::ExtAddress *aEui64,
                              const JoinerDiscerner *aDiscerner,
                              const char            *aPskd,
                              uint32_t               aTimeout)
{
    Error   error = kErrorNone;
    Joiner *joiner;
#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    bool isNewEntry;
#endif

    VerifyOrExit(mState == kStateActive, error = kErrorInvalidState);

    if (aDiscerner != nullptr)
    {
        VerifyOrExit(aDiscerner->IsValid(), error = kErrorInvalidArgs);
        joiner = FindJoinerEntry(*aDiscerner);
    }
    else
    {
        joiner = FindJoinerEntry(aEui64);
    }

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    isNewEntry = (joiner == nullptr);
#endif

    if (joiner == nullptr)
    {
        joiner = GetUnusedJoinerEntry();
    }

    VerifyOrExit(joiner != nullptr, error = kErrorNoBufs);

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    if (isNewEntry)
    {
        // A reused slot may still carry a previous occupant's group assignment;
        // a brand-new entry always starts ungrouped.
        joiner->mAssignedPanId = kNoAssignedPanId;
        joiner->mLastChildExtAddress.Clear();
    }

    // Every (re-)add makes this entry the one the Joiner Router expects next, and puts it back
    // in the not-yet-finalized state (e.g. when an already-onboarded device is onboarded again).
    joiner->mAddSequence = ++mAddSequenceCounter;
    joiner->mFinalized   = false;
#endif

    SuccessOrExit(error = joiner->mPskd.SetFrom(aPskd));

    if (aDiscerner != nullptr)
    {
        joiner->mType                = Joiner::kTypeDiscerner;
        joiner->mSharedId.mDiscerner = *aDiscerner;
    }
    else if (aEui64 != nullptr)
    {
        joiner->mType            = Joiner::kTypeEui64;
        joiner->mSharedId.mEui64 = *aEui64;
    }
    else
    {
        joiner->mType = Joiner::kTypeAny;
    }

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    if (aEui64 != nullptr)
    {
        // Group lookup and PAN decision (design doc §5.1, §10.2): a wildcard `*` or
        // `JoinerDiscerner` entry has no single EUI-64 to look up, so it's left ungrouped.
        error = ResolveJoinerPanId(*joiner, *aEui64);

        if (error != kErrorNone)
        {
            if (isNewEntry)
            {
                // Don't leave a half-configured entry behind.
                joiner->mType = Joiner::kTypeUnused;
            }

            ExitNow();
        }
    }
    else
    {
        joiner->mAssignedPanId = kNoAssignedPanId;
    }
#endif

    joiner->mExpirationTime = TimerMilli::GetNow() + Time::SecToMsec(aTimeout);

    mJoinerExpirationTimer.FireAtIfEarlier(joiner->mExpirationTime);

    SendCommissionerSet();

    LogJoinerEntry("Added", *joiner);

exit:
    return error;
}

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE

Error Commissioner::ResolveJoinerPanId(Joiner &aJoiner, const Mac::ExtAddress &aEui64)
{
    // Every EUI-64 Joiner entry ends up with a concrete PAN here: the Joiner Router has to
    // advertise it in the Discovery Response, before the joiner can be identified, and the
    // joiner keeps whatever PAN it was told.
    Error                  error              = kErrorNone;
    KeyManager            &keyMgr             = Get<KeyManager>();
    uint16_t               previousPanId      = aJoiner.mAssignedPanId;
    bool                   wasAlreadyAssigned = (previousPanId != kNoAssignedPanId);
    uint8_t                groupId            = FindGroupId(aEui64);
    uint16_t               newPanId           = kNoAssignedPanId;
    const PanIdAssignment *binding;

    if (groupId != kUnboundGroupId)
    {
        binding = keyMgr.FindGroupBinding(groupId);

        if (binding != nullptr)
        {
            // Group already has a bound PAN (a prior member seeded it) - reuse it.
            newPanId = binding->mPanId;
        }
        else
        {
            // First member of this group: allocate from the round-robin pool, then tag the
            // chosen entry with this group.
            const PanIdAssignment *fresh = AllocatePanId();

            // Fail closed on pool exhaustion for a brand-new group (design doc §8.2),
            // rather than silently falling back to the router's own PAN.
            VerifyOrExit(fresh != nullptr, error = kErrorNoBufs);

            IgnoreError(keyMgr.BindPanIdToGroup(fresh->mPanId, groupId));
            newPanId = fresh->mPanId;
        }
    }
    else
    {
        // Not in the Group Registry: the device gets its own "solo" PAN, the next free one from
        // the round-robin pool. A solo PAN already held by this entry is kept, so retries (and
        // refreshes of PSKd/timeout) don't burn further PANs.
        bool keepPrevious = false;

        if (wasAlreadyAssigned)
        {
            binding      = FindPanIdAssignment(keyMgr.GetPanIdPool(), keyMgr.GetPanIdPoolSize(), previousPanId);
            keepPrevious = (binding != nullptr) && (binding->mGroupId == kUnboundGroupId);

            for (const Joiner &other : mJoiners)
            {
                if ((&other != &aJoiner) && (other.mType != Joiner::kTypeUnused) &&
                    (other.mAssignedPanId == previousPanId))
                {
                    keepPrevious = false;
                    break;
                }
            }
        }

        if (keepPrevious)
        {
            newPanId = previousPanId;
        }
        else
        {
            const PanIdAssignment *fresh = AllocatePanId();

            // Ungrouped devices degrade to the router's own PAN when the pool is exhausted.
            newPanId = (fresh != nullptr) ? fresh->mPanId : Get<Mac::Mac>().GetPanId();
        }
    }

    LogMultiPan("ResolveJoinerPanId: groupId=%u prevPan=0x%04x newPan=0x%04x", groupId, previousPanId, newPanId);

    aJoiner.mAssignedPanId = newPanId;

    // Requirement (c): a device that already had a *different* assigned PAN gets
    // force-detached so it reattaches under the new one (design doc §10.2).
    if (wasAlreadyAssigned && (newPanId != previousPanId))
    {
        ForceDetachIfAttached(aJoiner);
    }

exit:
    return error;
}

uint16_t Commissioner::GetExpectedJoinerPanId(void) const
{
    const Joiner *expected  = nullptr;
    bool          ambiguous = false;

    for (const Joiner &joiner : mJoiners)
    {
        if ((joiner.mType == Joiner::kTypeUnused) || joiner.mFinalized || (joiner.mAssignedPanId == kNoAssignedPanId))
        {
            continue;
        }

        if (expected == nullptr)
        {
            expected = &joiner;
            continue;
        }

        ambiguous = ambiguous || (expected->mAssignedPanId != joiner.mAssignedPanId);

        if (joiner.mAddSequence > expected->mAddSequence)
        {
            expected = &joiner;
        }
    }

    if (ambiguous)
    {
        LogWarn("Several pending joiners with different PANs; advertising the most recently added (0x%04x)",
                expected->mAssignedPanId);
    }

    return (expected != nullptr) ? expected->mAssignedPanId : kNoAssignedPanId;
}

bool Commissioner::IsPanReserved(uint16_t aPanId) const
{
    bool reserved = false;

    for (const Joiner &joiner : mJoiners)
    {
        if ((joiner.mType != Joiner::kTypeUnused) && (joiner.mAssignedPanId == aPanId))
        {
            reserved = true;
            break;
        }
    }

    return reserved;
}

bool Commissioner::IsPanReservedCallback(const void *aContext, uint16_t aPanId)
{
    return static_cast<const Commissioner *>(aContext)->IsPanReserved(aPanId);
}

const PanIdAssignment *Commissioner::AllocatePanId(void)
{
    KeyManager &keyMgr = Get<KeyManager>();

    return keyMgr.AllocateNextPanId(&Commissioner::IsPanReservedCallback, this);
}

void Commissioner::RecordFinalizedJoinerChildAddress(const Mac::ExtAddress &aExtAddress, uint16_t aPanId)
{
    Joiner         *target = nullptr;
    Mac::ExtAddress noChildAddress;

    noChildAddress.Clear();

    for (Joiner &joiner : mJoiners)
    {
        if ((joiner.mType == Joiner::kTypeUnused) || !joiner.mFinalized || (joiner.mAssignedPanId != aPanId) ||
            (joiner.mLastChildExtAddress != noChildAddress))
        {
            continue;
        }

        if ((target == nullptr) || (joiner.mAddSequence > target->mAddSequence))
        {
            target = &joiner;
        }
    }

    if (target != nullptr)
    {
        target->mLastChildExtAddress = aExtAddress;
    }
}

void Commissioner::ForceDetachIfAttached(Joiner &aJoiner)
{
    Mac::ExtAddress noChildAddress;

    noChildAddress.Clear();

    if (aJoiner.mLastChildExtAddress != noChildAddress)
    {
        Child *child = Get<ChildTable>().FindChild(aJoiner.mLastChildExtAddress, Child::kInStateValid);

        if (child != nullptr)
        {
            Get<Mle::Mle>().RemoveNeighbor(*child);
            LogInfo("Force-detached previously joined child following a group PAN change");
        }
        // If not found, the device isn't currently attached - nothing to evict. It will
        // pick up the new `mAssignedPanId` the next time it does attach.
    }

    aJoiner.mLastChildExtAddress.Clear();
}

Commissioner::GroupMembership *Commissioner::FindGroupMembership(const Mac::ExtAddress &aEui64)
{
    GroupMembership *rval = nullptr;

    for (GroupMembership &entry : mGroupRegistry)
    {
        if ((entry.mGroupId != kUnboundGroupId) && (entry.mEui64 == aEui64))
        {
            rval = &entry;
            break;
        }
    }

    return rval;
}

Commissioner::GroupMembership *Commissioner::GetUnusedGroupMembership(void)
{
    GroupMembership *rval = nullptr;

    for (GroupMembership &entry : mGroupRegistry)
    {
        if (entry.mGroupId == kUnboundGroupId)
        {
            rval = &entry;
            break;
        }
    }

    return rval;
}

uint8_t Commissioner::FindGroupId(const Mac::ExtAddress &aEui64) const
{
    uint8_t groupId = kUnboundGroupId;

    for (const GroupMembership &entry : mGroupRegistry)
    {
        if ((entry.mGroupId != kUnboundGroupId) && (entry.mEui64 == aEui64))
        {
            groupId = entry.mGroupId;
            break;
        }
    }

    return groupId;
}

Error Commissioner::AddGroupMember(const Mac::ExtAddress &aEui64, uint8_t aGroupId)
{
    Error            error = kErrorNone;
    GroupMembership *entry;

    VerifyOrExit(aGroupId != kUnboundGroupId, error = kErrorInvalidArgs);

    entry = FindGroupMembership(aEui64);

    if (entry == nullptr)
    {
        entry = GetUnusedGroupMembership();
    }

    VerifyOrExit(entry != nullptr, error = kErrorNoBufs);

    entry->mEui64   = aEui64;
    entry->mGroupId = aGroupId;

exit:
    return error;
}

Error Commissioner::RemoveGroupMember(const Mac::ExtAddress &aEui64)
{
    Error            error = kErrorNone;
    GroupMembership *entry = FindGroupMembership(aEui64);
    Joiner          *joiner;

    VerifyOrExit(entry != nullptr, error = kErrorNotFound);

    entry->mGroupId = kUnboundGroupId;

    // If this EUI-64 already has a Joiner entry, re-resolve its PAN the same way
    // AddJoiner() would for an EUI-64 with no registry entry, force-detaching it if that
    // actually changes its PAN (design doc §11.1).
    joiner = FindJoinerEntry(&aEui64);

    if (joiner != nullptr)
    {
        IgnoreError(ResolveJoinerPanId(*joiner, aEui64));
    }

exit:
    return error;
}

Error Commissioner::RekeyGroup(uint8_t aGroupId)
{
    Error                  error  = kErrorNone;
    KeyManager            &keyMgr = Get<KeyManager>();
    const PanIdAssignment *oldBinding;
    uint16_t               oldPanId;
    const PanIdAssignment *fresh;

    VerifyOrExit(aGroupId != kUnboundGroupId, error = kErrorInvalidArgs);

    oldBinding = keyMgr.FindGroupBinding(aGroupId);
    VerifyOrExit(oldBinding != nullptr, error = kErrorNotFound);
    oldPanId = oldBinding->mPanId;

    fresh = AllocatePanId();
    VerifyOrExit(fresh != nullptr, error = kErrorNoBufs);

    IgnoreError(keyMgr.BindPanIdToGroup(oldPanId, kUnboundGroupId));
    IgnoreError(keyMgr.BindPanIdToGroup(fresh->mPanId, aGroupId));

    // Move every remaining member onto the new PAN and force-detach it (design doc §11.2).
    // A member already removed via RemoveGroupMember()/RemoveJoiner() first is no longer
    // in `mJoiners[]` and is skipped - it has no path back onto the new key.
    for (Joiner &joiner : mJoiners)
    {
        if ((joiner.mType != Joiner::kTypeUnused) && (joiner.mAssignedPanId == oldPanId))
        {
            joiner.mAssignedPanId = fresh->mPanId;
            ForceDetachIfAttached(joiner);
        }
    }

exit:
    return error;
}

Error Commissioner::DeleteGroup(uint8_t aGroupId)
{
    Error                  error  = kErrorNone;
    KeyManager            &keyMgr = Get<KeyManager>();
    const PanIdAssignment *binding;
    uint16_t               targetPanId;

    VerifyOrExit(aGroupId != kUnboundGroupId, error = kErrorInvalidArgs);

    binding = keyMgr.FindGroupBinding(aGroupId);
    VerifyOrExit(binding != nullptr, error = kErrorNotFound);
    targetPanId = binding->mPanId;

    IgnoreError(keyMgr.BindPanIdToGroup(targetPanId, kUnboundGroupId));

    for (GroupMembership &entry : mGroupRegistry)
    {
        if (entry.mGroupId == aGroupId)
        {
            entry.mGroupId = kUnboundGroupId;
        }
    }

    // Disband: every affected member falls back to its own solo PAN, same as an EUI-64
    // that was never grouped, and is force-detached to pick it up (design doc §11.3).
    for (Joiner &joiner : mJoiners)
    {
        if ((joiner.mType != Joiner::kTypeUnused) && (joiner.mAssignedPanId == targetPanId))
        {
            if (joiner.mType == Joiner::kTypeEui64)
            {
                // Falls back to a solo PAN (the group was just unbound) and force-detaches the
                // child if that changes its PAN.
                IgnoreError(ResolveJoinerPanId(joiner, joiner.mSharedId.mEui64));
            }
            else
            {
                joiner.mAssignedPanId = kNoAssignedPanId;
                ForceDetachIfAttached(joiner);
            }
        }
    }

exit:
    return error;
}

#endif // OPENTHREAD_CONFIG_MULTI_PAN_ENABLE

void Commissioner::Joiner::CopyToJoinerInfo(otJoinerInfo &aJoiner) const
{
    ClearAllBytes(aJoiner);

    switch (mType)
    {
    case kTypeAny:
        aJoiner.mType = OT_JOINER_INFO_TYPE_ANY;
        break;

    case kTypeEui64:
        aJoiner.mType            = OT_JOINER_INFO_TYPE_EUI64;
        aJoiner.mSharedId.mEui64 = mSharedId.mEui64;
        break;

    case kTypeDiscerner:
        aJoiner.mType                = OT_JOINER_INFO_TYPE_DISCERNER;
        aJoiner.mSharedId.mDiscerner = mSharedId.mDiscerner;
        break;

    case kTypeUnused:
        ExitNow();
    }

    aJoiner.mPskd           = mPskd;
    aJoiner.mExpirationTime = mExpirationTime - TimerMilli::GetNow();

exit:
    return;
}

Error Commissioner::GetNextJoinerInfo(uint16_t &aIterator, otJoinerInfo &aJoinerInfo) const
{
    Error error = kErrorNone;

    while (aIterator < GetArrayLength(mJoiners))
    {
        const Joiner &joiner = mJoiners[aIterator++];

        if (joiner.mType != Joiner::kTypeUnused)
        {
            joiner.CopyToJoinerInfo(aJoinerInfo);
            ExitNow();
        }
    }

    error = kErrorNotFound;

exit:
    return error;
}

Error Commissioner::RemoveJoiner(const Mac::ExtAddress *aEui64, const JoinerDiscerner *aDiscerner, uint32_t aDelay)
{
    Error   error = kErrorNone;
    Joiner *joiner;

    VerifyOrExit(mState == kStateActive, error = kErrorInvalidState);

    if (aDiscerner != nullptr)
    {
        VerifyOrExit(aDiscerner->IsValid(), error = kErrorInvalidArgs);
        joiner = FindJoinerEntry(*aDiscerner);
    }
    else
    {
        joiner = FindJoinerEntry(aEui64);
    }

    VerifyOrExit(joiner != nullptr, error = kErrorNotFound);

    RemoveJoiner(*joiner, aDelay);

exit:
    return error;
}

void Commissioner::RemoveJoiner(Joiner &aJoiner, uint32_t aDelay)
{
    if (aDelay > 0)
    {
        TimeMilli newExpirationTime = TimerMilli::GetNow() + Time::SecToMsec(aDelay);

        if (aJoiner.mExpirationTime > newExpirationTime)
        {
            aJoiner.mExpirationTime = newExpirationTime;
            mJoinerExpirationTimer.FireAtIfEarlier(newExpirationTime);
        }
    }
    else
    {
        RemoveJoinerEntry(aJoiner);
    }
}

Error Commissioner::SetProvisioningUrl(const char *aProvisioningUrl)
{
    return StringCopy(mProvisioningUrl, aProvisioningUrl, kStringCheckUtf8Encoding);
}

void Commissioner::HandleTimer(void)
{
    switch (mState)
    {
    case kStateDisabled:
        break;

    case kStatePetition:
        IgnoreError(SendPetition());
        break;

    case kStateActive:
        SendKeepAlive();
        break;
    }
}

void Commissioner::HandleJoinerExpirationTimer(void)
{
    NextFireTime nextTime;

    for (Joiner &joiner : mJoiners)
    {
        if (joiner.mType == Joiner::kTypeUnused)
        {
            continue;
        }

        if (joiner.mExpirationTime <= nextTime.GetNow())
        {
            LogDebg("removing joiner due to timeout or successfully joined");
            RemoveJoinerEntry(joiner);
        }
        else
        {
            nextTime.UpdateIfEarlier(joiner.mExpirationTime);
        }
    }

    mJoinerExpirationTimer.FireAtIfEarlier(nextTime);
}

Error Commissioner::SendMgmtCommissionerGetRequest(const uint8_t *aTlvs, uint8_t aLength)
{
    Error                   error = kErrorNone;
    OwnedPtr<Coap::Message> message;

    message.Reset(Get<Tmf::Agent>().AllocateAndInitPriorityConfirmablePostMessage(kUriCommissionerGet));
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    if (aLength > 0)
    {
        SuccessOrExit(error = Tlv::AppendTlv(*message, Tlv::kGet, aTlvs, aLength));
    }

    SuccessOrExit(error = Get<Tmf::Agent>().SendMessageToLeaderAloc(*message, HandleMgmtCommissionerGetResponse, this));
    message.Release();

    LogInfo("Sent %s to leader", UriToString<kUriCommissionerGet>());

exit:
    return error;
}

void Commissioner::HandleMgmtCommissionerGetResponse(Coap::Msg *aMsg, Error aResult)
{
    VerifyOrExit(aResult == kErrorNone && aMsg->GetCode() == Coap::kCodeChanged);
    LogInfo("Received %s response", UriToString<kUriCommissionerGet>());

exit:
    return;
}

Error Commissioner::SendMgmtCommissionerSetRequest(const CommissioningDataset &aDataset,
                                                   const uint8_t              *aTlvs,
                                                   uint8_t                     aLength)
{
    Error                   error = kErrorNone;
    OwnedPtr<Coap::Message> message;

    message.Reset(Get<Tmf::Agent>().AllocateAndInitPriorityConfirmablePostMessage(kUriCommissionerSet));
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    if (aDataset.IsLocatorSet())
    {
        SuccessOrExit(error = Tlv::Append<BorderAgentLocatorTlv>(*message, aDataset.GetLocator()));
    }

    if (aDataset.IsSessionIdSet())
    {
        SuccessOrExit(error = Tlv::Append<CommissionerSessionIdTlv>(*message, aDataset.GetSessionId()));
    }

    if (aDataset.IsSteeringDataSet())
    {
        const SteeringData &steeringData = aDataset.GetSteeringData();

        SuccessOrExit(error = SteeringDataTlv::AppendTo(*message, steeringData));
    }

    if (aDataset.IsJoinerUdpPortSet())
    {
        SuccessOrExit(error = Tlv::Append<JoinerUdpPortTlv>(*message, aDataset.GetJoinerUdpPort()));
    }

    if (aLength > 0)
    {
        SuccessOrExit(error = message->AppendBytes(aTlvs, aLength));
    }

    SuccessOrExit(error = Get<Tmf::Agent>().SendMessageToLeaderAloc(*message, HandleMgmtCommissionerSetResponse, this));
    message.Release();

    LogInfo("Sent %s to leader", UriToString<kUriCommissionerSet>());

exit:
    return error;
}

void Commissioner::HandleMgmtCommissionerSetResponse(Coap::Msg *aMsg, Error aResult)
{
    Error   error;
    uint8_t state;

    SuccessOrExit(error = aResult);
    VerifyOrExit(aMsg->GetCode() == Coap::kCodeChanged && Tlv::Find<StateTlv>(aMsg->mMessage, state) == kErrorNone &&
                     state != StateTlv::kPending,
                 error = kErrorParse);

    OT_UNUSED_VARIABLE(error);
exit:
    LogInfo("Received %s response: %s", UriToString<kUriCommissionerSet>(),
            error == kErrorNone ? StateTlv::StateToString(static_cast<StateTlv::State>(state)) : ErrorToString(error));
}

Error Commissioner::SendPetition(void)
{
    Error                   error = kErrorNone;
    OwnedPtr<Coap::Message> message;

    mTransmitAttempts++;

    message.Reset(Get<Tmf::Agent>().AllocateAndInitPriorityConfirmablePostMessage(kUriLeaderPetition));
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    SuccessOrExit(error = Tlv::Append<CommissionerIdTlv>(*message, mCommissionerId));

    SuccessOrExit(error = Get<Tmf::Agent>().SendMessageToLeaderAloc(*message, HandleLeaderPetitionResponse, this));
    message.Release();

    LogInfo("Sent %s", UriToString<kUriLeaderPetition>());

exit:
    return error;
}

void Commissioner::HandleLeaderPetitionResponse(Coap::Msg *aMsg, Error aResult)
{
    uint8_t state;
    bool    retransmit = false;

    VerifyOrExit(mState != kStateActive);
    VerifyOrExit(aResult == kErrorNone && aMsg->GetCode() == Coap::kCodeChanged,
                 retransmit = (mState == kStatePetition));

    LogInfo("Received %s response", UriToString<kUriLeaderPetition>());

    SuccessOrExit(Tlv::Find<StateTlv>(aMsg->mMessage, state));
    VerifyOrExit(state == StateTlv::kAccept, IgnoreError(Stop(kDoNotSendKeepAlive)));

    SuccessOrExit(Tlv::Find<CommissionerSessionIdTlv>(aMsg->mMessage, mSessionId));

    // reject this session by sending KeepAlive reject if commissioner is in disabled state
    // this could happen if commissioner is stopped by API during petitioning
    if (mState == kStateDisabled)
    {
        SendKeepAlive(mSessionId);
        ExitNow();
    }

    Get<Mle::Mle>().ComposeCommissionerAloc(mSessionId, mCommissionerAloc.GetAddress());
    Get<ThreadNetif>().AddUnicastAddress(mCommissionerAloc);

    SetState(kStateActive);

    mTransmitAttempts = 0;
    mTimer.Start(Time::SecToMsec(kKeepAliveTimeout) / 2);

exit:

    if (retransmit)
    {
        if (mTransmitAttempts >= kPetitionRetryCount)
        {
            IgnoreError(Stop(kDoNotSendKeepAlive));
        }
        else
        {
            mTimer.Start(Time::SecToMsec(kPetitionRetryDelay));
        }
    }
}

void Commissioner::SendKeepAlive(void) { SendKeepAlive(mSessionId); }

void Commissioner::SendKeepAlive(uint16_t aSessionId)
{
    Error                   error = kErrorNone;
    OwnedPtr<Coap::Message> message;

    message.Reset(Get<Tmf::Agent>().AllocateAndInitPriorityConfirmablePostMessage(kUriLeaderKeepAlive));
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    SuccessOrExit(
        error = Tlv::Append<StateTlv>(*message, (mState == kStateActive) ? StateTlv::kAccept : StateTlv::kReject));

    SuccessOrExit(error = Tlv::Append<CommissionerSessionIdTlv>(*message, aSessionId));

    SuccessOrExit(error = Get<Tmf::Agent>().SendMessageToLeaderAloc(*message, HandleLeaderKeepAliveResponse, this));
    message.Release();

    LogInfo("Sent %s", UriToString<kUriLeaderKeepAlive>());

exit:
    LogWarnOnError(error, "send keep alive");
}

void Commissioner::HandleLeaderKeepAliveResponse(Coap::Msg *aMsg, Error aResult)
{
    uint8_t state;

    VerifyOrExit(mState == kStateActive);
    VerifyOrExit(aResult == kErrorNone && aMsg->GetCode() == Coap::kCodeChanged,
                 IgnoreError(Stop(kDoNotSendKeepAlive)));

    LogInfo("Received %s response", UriToString<kUriLeaderKeepAlive>());

    SuccessOrExit(Tlv::Find<StateTlv>(aMsg->mMessage, state));
    VerifyOrExit(state == StateTlv::kAccept, IgnoreError(Stop(kDoNotSendKeepAlive)));

    mTimer.Start(Time::SecToMsec(kKeepAliveTimeout) / 2);

exit:
    return;
}

template <> void Commissioner::HandleTmf<kUriRelayRx>(Coap::Msg &aMsg)
{
    Error                    error;
    uint16_t                 joinerPort;
    Ip6::InterfaceIdentifier joinerIid;
    uint16_t                 joinerRloc;
    Ip6::MessageInfo         joinerMessageInfo;
    OffsetRange              offsetRange;

    VerifyOrExit(mState == kStateActive, error = kErrorInvalidState);

    VerifyOrExit(aMsg.IsNonConfirmable());

    SuccessOrExit(error = Tlv::Find<JoinerUdpPortTlv>(aMsg.mMessage, joinerPort));
    SuccessOrExit(error = Tlv::Find<JoinerIidTlv>(aMsg.mMessage, joinerIid));
    SuccessOrExit(error = Tlv::Find<JoinerRouterLocatorTlv>(aMsg.mMessage, joinerRloc));

    SuccessOrExit(error = Tlv::FindTlvValueOffsetRange(aMsg.mMessage, Tlv::kJoinerDtlsEncapsulation, offsetRange));

    if (!Get<Tmf::SecureAgent>().IsConnectionActive())
    {
        Mac::ExtAddress receivedId;
        Joiner         *joiner;

        mJoinerIid = joinerIid;
        receivedId.SetFromIid(mJoinerIid);

        joiner = FindBestMatchingJoinerEntry(receivedId);
        VerifyOrExit(joiner != nullptr);

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
        if (joiner->mAssignedPanId != kNoAssignedPanId)
        {
            // The joiner keeps the PAN it learned from the Discovery Response, which the Joiner
            // Router had to pick before it could tell who was asking. Make sure it was this
            // joiner's PAN; otherwise commissioning would hand it a PAN other than the one it is
            // actually on (and not the one it was meant for).
            uint16_t advertisedPanId = kNoAssignedPanId;

            if (!Get<JoinerRouter>().PeekPendingPanId(advertisedPanId))
            {
                // No Discovery context (e.g. the joiner skipped discovery): this joiner is it.
                joiner->mAddSequence = ++mAddSequenceCounter;
                IgnoreError(Get<JoinerRouter>().SelectPanIdForDiscovery());
            }

            if (!Get<JoinerRouter>().PeekPendingPanId(advertisedPanId) || (advertisedPanId != joiner->mAssignedPanId))
            {
                // Drop this attempt. Making this joiner the expected one means its retry will be
                // advertised the right PAN.
                joiner->mAddSequence = ++mAddSequenceCounter;
                LogMultiPan("PAN mismatch: joiner expects 0x%04x but 0x%04x was advertised; dropping session",
                            joiner->mAssignedPanId, advertisedPanId);
                ExitNow();
            }
        }
#endif

        Get<Tmf::SecureAgent>().SetPsk(joiner->mPskd);
#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
        LogMultiPan("mActiveJoiner set: prev=%s new type=%u assignedPan=0x%04x", mActiveJoiner ? "stale" : "null",
                    static_cast<unsigned>(joiner->mType), joiner->mAssignedPanId);
#endif
        mActiveJoiner = joiner;

        mJoinerSessionTimer.Start(kJoinerSessionTimeoutMillis);

        LogJoinerEntry("Starting new session with", *joiner);
        SignalJoinerEvent(kJoinerEventStart, joiner);
    }
    else
    {
        if (mJoinerIid != joinerIid)
        {
            LogNote("Ignore %s (%s, 0x%04x), session in progress with (%s, 0x%04x)", UriToString<kUriRelayRx>(),
                    joinerIid.ToString().AsCString(), joinerRloc, mJoinerIid.ToString().AsCString(), mJoinerRloc);

            ExitNow();
        }
    }

    mJoinerPort = joinerPort;
    mJoinerRloc = joinerRloc;

    LogInfo("Received %s (%s, 0x%04x)", UriToString<kUriRelayRx>(), mJoinerIid.ToString().AsCString(), mJoinerRloc);

    aMsg.mMessage.SetOffset(offsetRange.GetOffset());
    SuccessOrExit(error = aMsg.mMessage.SetLength(offsetRange.GetEndOffset()));

    Get<Mle::Mle>().ComposeMeshLocalAddress(mJoinerIid, joinerMessageInfo.GetPeerAddr());
    joinerMessageInfo.SetPeerPort(mJoinerPort);

    Get<Tmf::SecureAgent>().HandleReceive(aMsg.mMessage, joinerMessageInfo);

exit:
    return;
}

void Commissioner::HandleJoinerSessionTimer(void)
{
    if (mActiveJoiner != nullptr)
    {
        LogJoinerEntry("Timed out session with", *mActiveJoiner);
    }

    Get<Tmf::SecureAgent>().Disconnect();
}

template <> void Commissioner::HandleTmf<kUriDatasetChanged>(Coap::Msg &aMsg)
{
    VerifyOrExit(mState == kStateActive);
    VerifyOrExit(aMsg.IsConfirmable());

    LogInfo("Received %s", UriToString<kUriDatasetChanged>());

    SuccessOrExit(Get<Tmf::Agent>().SendAckResponse(aMsg));

    LogInfo("Sent %s ack", UriToString<kUriDatasetChanged>());

exit:
    return;
}

template <> void Commissioner::HandleTmf<kUriJoinerFinalize>(Coap::Msg &aMsg)
{
    StateTlv::State                state = StateTlv::kAccept;
    ProvisioningUrlTlv::StringType provisioningUrl;

    VerifyOrExit(mState == kStateActive);

    LogInfo("Received %s", UriToString<kUriJoinerFinalize>());

    switch (Tlv::Find<ProvisioningUrlTlv>(aMsg.mMessage, provisioningUrl))
    {
    case kErrorNone:
        if (!StringMatch(provisioningUrl, mProvisioningUrl))
        {
            state = StateTlv::kReject;
        }
        break;

    case kErrorNotFound:
        // Fail closed: when the commissioner has a provisioning URL
        // configured, a `JOIN_FIN.req` that omits the Provisioning URL TLV
        // must be rejected as well; otherwise the URL check is joiner-opt-in
        // and omitting the TLV skips it. Joiners that predate the TLV can
        // still join commissioners with no provisioning URL configured.
        if (mProvisioningUrl[0] != kNullChar)
        {
            state = StateTlv::kReject;
        }
        break;

    default:
        ExitNow();
    }

#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
    LogCertMessage("[THCI] direction=recv | type=JOIN_FIN.req |", aMsg.mMessage);
#endif

    SendJoinFinalizeResponse(aMsg.mMessage, state);

exit:
    return;
}

void Commissioner::SendJoinFinalizeResponse(const Coap::Message &aRequest, StateTlv::State aState)
{
    Error          error = kErrorNone;
    Coap::Message *message;

    message = Get<Tmf::SecureAgent>().AllocateAndInitPriorityResponseFor(aRequest);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    message->SetOffset(message->GetLength());
    message->SetSubType(Message::kSubTypeJoinerFinalizeResponse);

    SuccessOrExit(error = Tlv::Append<StateTlv>(*message, aState));

#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
    LogCertMessage("[THCI] direction=send | type=JOIN_FIN.rsp |", *message);
#endif

    SuccessOrExit(error = Get<Tmf::SecureAgent>().SendMessage(*message));

    SignalJoinerEvent(kJoinerEventFinalize, mActiveJoiner);

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    if (mActiveJoiner != nullptr)
    {
        // This joiner is done commissioning: it is no longer the one the next Discovery
        // Response should be advertised for.
        mActiveJoiner->mFinalized = true;
    }
#endif

    if ((mActiveJoiner != nullptr) && (mActiveJoiner->mType != Joiner::kTypeAny))
    {
        // Remove after kRemoveJoinerDelay (seconds)
        RemoveJoiner(*mActiveJoiner, kRemoveJoinerDelay);
    }

    LogInfo("Sent %s response", UriToString<kUriJoinerFinalize>());

exit:
    FreeMessageOnError(message, error);
}

Error Commissioner::SendRelayTransmit(void *aContext, Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    return static_cast<Commissioner *>(aContext)->SendRelayTransmit(aMessage, aMessageInfo);
}

Error Commissioner::SendRelayTransmit(Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    OT_UNUSED_VARIABLE(aMessageInfo);

    Error                   error = kErrorNone;
    OffsetRange             offsetRange;
    OwnedPtr<Coap::Message> message;
    Kek                     kek;

    Get<KeyManager>().ExtractKek(kek);

    message.Reset(Get<Tmf::Agent>().AllocateAndInitPriorityNonConfirmablePostMessage(kUriRelayTx));
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    SuccessOrExit(error = Tlv::Append<JoinerUdpPortTlv>(*message, mJoinerPort));
    SuccessOrExit(error = Tlv::Append<JoinerIidTlv>(*message, mJoinerIid));
    SuccessOrExit(error = Tlv::Append<JoinerRouterLocatorTlv>(*message, mJoinerRloc));

    if (aMessage.GetSubType() == Message::kSubTypeJoinerFinalizeResponse)
    {
        SuccessOrExit(error = Tlv::Append<JoinerRouterKekTlv>(*message, kek));
    }

    offsetRange.InitFromMessageFullLength(aMessage);
    SuccessOrExit(
        error = Tlv::AppendTlvWithValueFromMessage(*message, Tlv::kJoinerDtlsEncapsulation, aMessage, offsetRange));

    SuccessOrExit(error = Get<Tmf::Agent>().SendMessageToRloc(*message, mJoinerRloc));
    message.Release();

    aMessage.Free();

exit:
    return error;
}

Error Commissioner::SendAnnounceBeginRequest(uint32_t            aChannelMask,
                                             uint8_t             aCount,
                                             uint16_t            aPeriod,
                                             const Ip6::Address &aAddress)
{
    Error          error   = kErrorNone;
    Coap::Message *message = nullptr;

    VerifyOrExit(IsActive(), error = kErrorInvalidState);

    message = Get<Tmf::Agent>().AllocateAndInitPriorityPostMessageTo(kUriAnnounceBegin, aAddress);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    SuccessOrExit(error = Tlv::Append<CommissionerSessionIdTlv>(*message, GetSessionId()));

    SuccessOrExit(error = ChannelMaskTlv::AppendTo(*message, aChannelMask));

    SuccessOrExit(error = Tlv::Append<CountTlv>(*message, aCount));
    SuccessOrExit(error = Tlv::Append<PeriodTlv>(*message, aPeriod));

    SuccessOrExit(error = Get<Tmf::Agent>().SendMessageTo(*message, aAddress));

    LogInfo("Sent %s", UriToString<kUriAnnounceBegin>());

exit:
    FreeMessageOnError(message, error);
    return error;
}

Error Commissioner::SendEnergyScanQuery(uint32_t             aChannelMask,
                                        uint8_t              aCount,
                                        uint16_t             aPeriod,
                                        uint16_t             aScanDuration,
                                        const Ip6::Address  &aAddress,
                                        EnergyReportCallback aCallback,
                                        void                *aContext)
{
    Error          error   = kErrorNone;
    Coap::Message *message = nullptr;

    VerifyOrExit(IsActive(), error = kErrorInvalidState);

    message = Get<Tmf::Agent>().AllocateAndInitPriorityPostMessageTo(kUriEnergyScan, aAddress);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    SuccessOrExit(error = Tlv::Append<CommissionerSessionIdTlv>(*message, GetSessionId()));

    SuccessOrExit(error = ChannelMaskTlv::AppendTo(*message, aChannelMask));

    SuccessOrExit(error = Tlv::Append<CountTlv>(*message, aCount));
    SuccessOrExit(error = Tlv::Append<PeriodTlv>(*message, aPeriod));
    SuccessOrExit(error = Tlv::Append<ScanDurationTlv>(*message, aScanDuration));

    SuccessOrExit(error = Get<Tmf::Agent>().SendMessageTo(*message, aAddress));

    LogInfo("Sent %s", UriToString<kUriEnergyScan>());

    mEnergyReportCallback.Set(aCallback, aContext);

exit:
    FreeMessageOnError(message, error);
    return error;
}

template <> void Commissioner::HandleTmf<kUriEnergyReport>(Coap::Msg &aMsg)
{
    uint32_t    mask;
    OffsetRange valueOffsetRange;
    uint8_t     results[kMaxEnergyScanResults];

    VerifyOrExit(aMsg.IsConfirmable());

    LogInfo("Received %s", UriToString<kUriEnergyReport>());

    SuccessOrExit(ChannelMaskTlv::FindIn(aMsg.mMessage, mask));

    SuccessOrExit(Tlv::FindTlvValueOffsetRange(aMsg.mMessage, Tlv::kEnergyList, valueOffsetRange));
    valueOffsetRange.ShrinkLength(sizeof(results));
    aMsg.mMessage.ReadBytes(valueOffsetRange, results);

    mEnergyReportCallback.InvokeIfSet(mask, results, static_cast<uint8_t>(valueOffsetRange.GetLength()));

    SuccessOrExit(Get<Tmf::Agent>().SendAckResponse(aMsg));

    LogInfo("Sent %s ack", UriToString<kUriEnergyReport>());

exit:
    return;
}

Error Commissioner::SendPanIdQuery(uint16_t              aPanId,
                                   uint32_t              aChannelMask,
                                   const Ip6::Address   &aAddress,
                                   PanIdConflictCallback aCallback,
                                   void                 *aContext)
{
    Error          error   = kErrorNone;
    Coap::Message *message = nullptr;

    VerifyOrExit(IsActive(), error = kErrorInvalidState);

    message = Get<Tmf::Agent>().AllocateAndInitPriorityPostMessageTo(kUriPanIdQuery, aAddress);
    VerifyOrExit(message != nullptr, error = kErrorNoBufs);

    SuccessOrExit(error = Tlv::Append<CommissionerSessionIdTlv>(*message, GetSessionId()));

    SuccessOrExit(error = ChannelMaskTlv::AppendTo(*message, aChannelMask));

    SuccessOrExit(error = Tlv::Append<PanIdTlv>(*message, aPanId));

    SuccessOrExit(error = Get<Tmf::Agent>().SendMessageTo(*message, aAddress));

    LogInfo("Sent %s", UriToString<kUriPanIdQuery>());

    mPanIdConflictCallback.Set(aCallback, aContext);

exit:
    FreeMessageOnError(message, error);
    return error;
}

template <> void Commissioner::HandleTmf<kUriPanIdConflict>(Coap::Msg &aMsg)
{
    uint16_t panId;
    uint32_t mask;

    VerifyOrExit(aMsg.IsConfirmable());

    LogInfo("Received %s", UriToString<kUriPanIdConflict>());

    SuccessOrExit(Tlv::Find<PanIdTlv>(aMsg.mMessage, panId));

    SuccessOrExit(ChannelMaskTlv::FindIn(aMsg.mMessage, mask));

    mPanIdConflictCallback.InvokeIfSet(panId, mask);

    SuccessOrExit(Get<Tmf::Agent>().SendAckResponse(aMsg));

    LogInfo("Sent %s response", UriToString<kUriPanIdConflict>());

exit:
    return;
}

// LCOV_EXCL_START

#if OT_SHOULD_LOG_AT(OT_LOG_LEVEL_INFO)

const char *Commissioner::StateToString(State aState)
{
#define StateMapList(_)           \
    _(kStateDisabled, "disabled") \
    _(kStatePetition, "petition") \
    _(kStateActive, "active")

    DefineEnumStringArray(StateMapList);

    return kStrings[aState];
}

void Commissioner::LogJoinerEntry(const char *aAction, const Joiner &aJoiner) const
{
    switch (aJoiner.mType)
    {
    case Joiner::kTypeUnused:
        break;

    case Joiner::kTypeAny:
        LogInfo("%s Joiner (any, %s)", aAction, aJoiner.mPskd.GetAsCString());
        break;

    case Joiner::kTypeEui64:
        LogInfo("%s Joiner (eui64:%s, %s)", aAction, aJoiner.mSharedId.mEui64.ToString().AsCString(),
                aJoiner.mPskd.GetAsCString());
        break;

    case Joiner::kTypeDiscerner:
        LogInfo("%s Joiner (disc:%s, %s)", aAction, aJoiner.mSharedId.mDiscerner.ToString().AsCString(),
                aJoiner.mPskd.GetAsCString());
        break;
    }
}

#else

void Commissioner::LogJoinerEntry(const char *, const Joiner &) const {}

#endif // OT_SHOULD_LOG_AT(OT_LOG_LEVEL_INFO)

// LCOV_EXCL_STOP

} // namespace MeshCoP
} // namespace ot

#endif // OPENTHREAD_FTD && OPENTHREAD_CONFIG_COMMISSIONER_ENABLE
