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
 *   This file includes definitions for the Commissioner role.
 */

#ifndef OT_CORE_MESHCOP_COMMISSIONER_HPP_
#define OT_CORE_MESHCOP_COMMISSIONER_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_FTD && OPENTHREAD_CONFIG_COMMISSIONER_ENABLE

#include <openthread/commissioner.h>

#include "coap/coap_secure.hpp"
#include "common/as_core_type.hpp"
#include "common/callback.hpp"
#include "common/clearable.hpp"
#include "common/locator.hpp"
#include "common/log.hpp"
#include "common/non_copyable.hpp"
#include "common/timer.hpp"
#include "mac/mac_types.hpp"
#include "meshcop/secure_transport.hpp"
#include "net/ip6_address.hpp"
#include "net/udp6.hpp"
#include "thread/key_manager.hpp"
#include "thread/mle.hpp"
#include "thread/tmf.hpp"

namespace ot {

namespace MeshCoP {

#if !OPENTHREAD_CONFIG_SECURE_TRANSPORT_ENABLE
#error "Commissioner feature requires `OPENTHREAD_CONFIG_SECURE_TRANSPORT_ENABLE`"
#endif

class Commissioner : public InstanceLocator, private NonCopyable
{
    friend class Tmf::Agent;
    friend class Tmf::SecureAgent;

public:
    /**
     * Type represents the Commissioner State.
     */
    enum State : uint8_t
    {
        kStateDisabled = OT_COMMISSIONER_STATE_DISABLED, ///< Disabled.
        kStatePetition = OT_COMMISSIONER_STATE_PETITION, ///< Petitioning to become a Commissioner.
        kStateActive   = OT_COMMISSIONER_STATE_ACTIVE,   ///< Active Commissioner.
    };

    /**
     * Type represents Joiner Event.
     */
    enum JoinerEvent : uint8_t
    {
        kJoinerEventStart     = OT_COMMISSIONER_JOINER_START,
        kJoinerEventConnected = OT_COMMISSIONER_JOINER_CONNECTED,
        kJoinerEventFinalize  = OT_COMMISSIONER_JOINER_FINALIZE,
        kJoinerEventEnd       = OT_COMMISSIONER_JOINER_END,
        kJoinerEventRemoved   = OT_COMMISSIONER_JOINER_REMOVED,
    };

    typedef otCommissionerStateCallback         StateCallback;         ///< State change callback type.
    typedef otCommissionerJoinerCallback        JoinerCallback;        ///< Joiner state change callback type.
    typedef otCommissionerEnergyReportCallback  EnergyReportCallback;  ///< Energy report callback type.
    typedef otCommissionerPanIdConflictCallback PanIdConflictCallback; ///< PAN ID conflict callback type.

    /**
     * Initializes the Commissioner object.
     *
     * @param[in]  aInstance     A reference to the OpenThread instance.
     */
    explicit Commissioner(Instance &aInstance);

    /**
     * Starts the Commissioner service.
     *
     * @param[in]  aStateCallback    A pointer to a function that is called when the commissioner state changes.
     * @param[in]  aJoinerCallback   A pointer to a function that is called when a joiner event occurs.
     * @param[in]  aCallbackContext  A pointer to application-specific context.
     *
     * @retval kErrorNone           Successfully started the Commissioner service.
     * @retval kErrorAlready        Commissioner is already started.
     * @retval kErrorInvalidState   Device is not currently attached to a network.
     */
    Error Start(StateCallback aStateCallback, JoinerCallback aJoinerCallback, void *aCallbackContext);

    /**
     * Stops the Commissioner service.
     *
     * @retval kErrorNone     Successfully stopped the Commissioner service.
     * @retval kErrorAlready  Commissioner is already stopped.
     */
    Error Stop(void) { return Stop(kSendKeepAliveToResign); }

    /**
     * Returns the Commissioner Id.
     *
     * @returns The Commissioner Id.
     */
    const char *GetId(void) const { return mCommissionerId; }

    /**
     * Sets the Commissioner Id.
     *
     * @param[in]  aId   A pointer to a string character array. Must be null terminated.
     *
     * @retval kErrorNone           Successfully set the Commissioner Id.
     * @retval kErrorInvalidArgs    Given name is too long.
     * @retval kErrorInvalidState   The commissioner is active and id cannot be changed.
     */
    Error SetId(const char *aId);

    /**
     * Clears all Joiner entries.
     */
    void ClearJoiners(void);

    /**
     * Adds a Joiner entry accepting any Joiner.
     *
     * @param[in]  aPskd         A pointer to the PSKd.
     * @param[in]  aTimeout      A time after which a Joiner is automatically removed, in seconds.
     *
     * @retval kErrorNone          Successfully added the Joiner.
     * @retval kErrorNoBufs        No buffers available to add the Joiner.
     * @retval kErrorInvalidState  Commissioner service is not started.
     */
    Error AddJoinerAny(const char *aPskd, uint32_t aTimeout) { return AddJoiner(nullptr, nullptr, aPskd, aTimeout); }

    /**
     * Adds a Joiner entry.
     *
     * @param[in]  aEui64        The Joiner's IEEE EUI-64.
     * @param[in]  aPskd         A pointer to the PSKd.
     * @param[in]  aTimeout      A time after which a Joiner is automatically removed, in seconds.
     *
     * @retval kErrorNone          Successfully added the Joiner.
     * @retval kErrorNoBufs        No buffers available to add the Joiner.
     * @retval kErrorInvalidState  Commissioner service is not started.
     */
    Error AddJoiner(const Mac::ExtAddress &aEui64, const char *aPskd, uint32_t aTimeout)
    {
        return AddJoiner(&aEui64, nullptr, aPskd, aTimeout);
    }

    /**
     * Adds a Joiner entry with a Joiner Discerner.
     *
     * @param[in]  aDiscerner  A Joiner Discerner.
     * @param[in]  aPskd       A pointer to the PSKd.
     * @param[in]  aTimeout    A time after which a Joiner is automatically removed, in seconds.
     *
     * @retval kErrorNone          Successfully added the Joiner.
     * @retval kErrorNoBufs        No buffers available to add the Joiner.
     * @retval kErrorInvalidState  Commissioner service is not started.
     */
    Error AddJoiner(const JoinerDiscerner &aDiscerner, const char *aPskd, uint32_t aTimeout)
    {
        return AddJoiner(nullptr, &aDiscerner, aPskd, aTimeout);
    }

    /**
     * Get joiner info at aIterator position.
     *
     * @param[in,out]   aIterator   A iterator to the index of the joiner.
     * @param[out]      aJoiner     A reference to Joiner info.
     *
     * @retval kErrorNone       Successfully get the Joiner info.
     * @retval kErrorNotFound   Not found next Joiner.
     */
    Error GetNextJoinerInfo(uint16_t &aIterator, otJoinerInfo &aJoiner) const;

    /**
     * Removes a Joiner entry accepting any Joiner.
     *
     * @param[in]  aDelay         The delay to remove Joiner (in seconds).
     *
     * @retval kErrorNone          Successfully added the Joiner.
     * @retval kErrorNotFound      The Joiner entry accepting any Joiner was not found.
     * @retval kErrorInvalidState  Commissioner service is not started.
     */
    Error RemoveJoinerAny(uint32_t aDelay) { return RemoveJoiner(nullptr, nullptr, aDelay); }

    /**
     * Removes a Joiner entry.
     *
     * @param[in]  aEui64         The Joiner's IEEE EUI-64.
     * @param[in]  aDelay         The delay to remove Joiner (in seconds).
     *
     * @retval kErrorNone          Successfully added the Joiner.
     * @retval kErrorNotFound      The Joiner specified by @p aEui64 was not found.
     * @retval kErrorInvalidState  Commissioner service is not started.
     */
    Error RemoveJoiner(const Mac::ExtAddress &aEui64, uint32_t aDelay)
    {
        return RemoveJoiner(&aEui64, nullptr, aDelay);
    }

    /**
     * Removes a Joiner entry.
     *
     * @param[in]  aDiscerner     A Joiner Discerner.
     * @param[in]  aDelay         The delay to remove Joiner (in seconds).
     *
     * @retval kErrorNone          Successfully added the Joiner.
     * @retval kErrorNotFound      The Joiner specified by @p aEui64 was not found.
     * @retval kErrorInvalidState  Commissioner service is not started.
     */
    Error RemoveJoiner(const JoinerDiscerner &aDiscerner, uint32_t aDelay)
    {
        return RemoveJoiner(nullptr, &aDiscerner, aDelay);
    }

    /**
     * Sentinel `Joiner::mAssignedPanId` value meaning "no group-assigned PAN - use the
     * existing per-device round-robin allocator instead".
     */
    static constexpr uint16_t kNoAssignedPanId = 0xffff;

    /**
     * Maps a device's EUI-64 to a Group ID in the preconfigured Group Registry.
     *
     * If the device already has a Joiner entry (added via AddJoiner()) whose resolved PAN
     * changes as a result, that Joiner is force-detached (see RemoveNeighbor()) so it
     * rejoins on the new PAN.
     *
     * @param[in]  aEui64    The device's IEEE EUI-64.
     * @param[in]  aGroupId  The Group ID to associate with @p aEui64. Must be non-zero.
     *
     * @retval kErrorNone          Successfully added (or updated) the mapping.
     * @retval kErrorInvalidArgs   @p aGroupId is the reserved "no group" value (0).
     * @retval kErrorNoBufs        No space left in the Group Registry.
     */
    Error AddGroupMember(const Mac::ExtAddress &aEui64, uint8_t aGroupId);

    /**
     * Un-maps a device from its group, per §11.1 of the group-PAN design: the device falls
     * back to the plain per-device round-robin allocator, the way an EUI-64 with no registry
     * entry always has. The rest of the group keeps its existing PAN/Network Key.
     *
     * @param[in]  aEui64  The device's IEEE EUI-64.
     *
     * @retval kErrorNone       Successfully removed the mapping.
     * @retval kErrorNotFound   @p aEui64 has no Group Registry entry.
     */
    Error RemoveGroupMember(const Mac::ExtAddress &aEui64);

    /**
     * Rekeys a group: allocates a fresh PAN/Network Key and moves every current member of
     * @p aGroupId onto it, force-detaching each one that is currently attached.
     *
     * @param[in]  aGroupId  The Group ID to rekey.
     *
     * @retval kErrorNone       Successfully rekeyed the group.
     * @retval kErrorNotFound   @p aGroupId has no current PAN binding (no member has joined yet).
     * @retval kErrorNoBufs     The PAN ID pool has no free entry for the new PAN.
     */
    Error RekeyGroup(uint8_t aGroupId);

    /**
     * Disbands a group: frees its PAN binding and every member's Group Registry entry, and
     * force-detaches each currently-assigned member so it falls back to a solo PAN.
     *
     * @param[in]  aGroupId  The Group ID to delete.
     *
     * @retval kErrorNone       Successfully deleted the group.
     * @retval kErrorNotFound   @p aGroupId has no current PAN binding (no member has joined yet).
     */
    Error DeleteGroup(uint8_t aGroupId);

    /**
     * Returns the PAN ID assigned (via the Group Registry) to the Joiner currently being
     * commissioned. Used by `JoinerRouter` to bypass the round-robin allocator when the PAN
     * was already decided at `AddJoiner()` time.
     *
     * @returns The assigned PAN ID, or `kNoAssignedPanId` if there is no active Joiner or it
     *          has no group assignment.
     */
    uint16_t GetActiveJoinerAssignedPanId(void) const
    {
        return (mActiveJoiner != nullptr) ? mActiveJoiner->mAssignedPanId : kNoAssignedPanId;
    }

    /**
     * Records the operational Extended Address the currently active Joiner just attached
     * with, so a later group change can find and force-detach it. No-op if there is no
     * active Joiner.
     *
     * @param[in]  aExtAddress  The attaching child's Extended Address.
     */
    void RecordActiveJoinerChildAddress(const Mac::ExtAddress &aExtAddress)
    {
        if (mActiveJoiner != nullptr)
        {
            mActiveJoiner->mLastChildExtAddress = aExtAddress;
        }
    }

    /**
     * Gets the Provisioning URL.
     *
     * @returns A pointer to char buffer containing the URL string.
     */
    const char *GetProvisioningUrl(void) const { return mProvisioningUrl; }

    /**
     * Sets the Provisioning URL.
     *
     * @param[in]  aProvisioningUrl  A pointer to the Provisioning URL (may be `nullptr` to set URL to empty string).
     *
     * @retval kErrorNone         Successfully set the Provisioning URL.
     * @retval kErrorInvalidArgs  @p aProvisioningUrl is invalid (too long).
     */
    Error SetProvisioningUrl(const char *aProvisioningUrl);

    /**
     * Returns the Commissioner Session ID.
     *
     * @returns The Commissioner Session ID.
     */
    uint16_t GetSessionId(void) const { return mSessionId; }

    /**
     * Indicates whether or not the Commissioner role is active.
     *
     * @returns TRUE if the Commissioner role is active, FALSE otherwise.
     */
    bool IsActive(void) const { return mState == kStateActive; }

    /**
     * Indicates whether or not the Commissioner role is disabled.
     *
     * @returns TRUE if the Commissioner role is disabled, FALSE otherwise.
     */
    bool IsDisabled(void) const { return mState == kStateDisabled; }

    /**
     * Gets the Commissioner State.
     *
     * @returns The Commissioner State.
     */
    State GetState(void) const { return mState; }

    /**
     * Sends MGMT_COMMISSIONER_GET.
     *
     * @param[in]  aTlvs        A pointer to Commissioning Data TLVs.
     * @param[in]  aLength      The length of requested TLVs in bytes.
     *
     * @retval kErrorNone          Send MGMT_COMMISSIONER_GET successfully.
     * @retval kErrorNoBufs        Insufficient buffer space to send.
     * @retval kErrorInvalidState  Commissioner service is not started.
     */
    Error SendMgmtCommissionerGetRequest(const uint8_t *aTlvs, uint8_t aLength);

    /**
     * Sends MGMT_COMMISSIONER_SET.
     *
     * @param[in]  aDataset     A reference to Commissioning Data.
     * @param[in]  aTlvs        A pointer to user specific Commissioning Data TLVs.
     * @param[in]  aLength      The length of user specific TLVs in bytes.
     *
     * @retval kErrorNone          Send MGMT_COMMISSIONER_SET successfully.
     * @retval kErrorNoBufs        Insufficient buffer space to send.
     * @retval kErrorInvalidState  Commissioner service is not started.
     */
    Error SendMgmtCommissionerSetRequest(const CommissioningDataset &aDataset, const uint8_t *aTlvs, uint8_t aLength);

    /**
     * Sends a Announce Begin message.
     *
     * @param[in]  aChannelMask   The channel mask value.
     * @param[in]  aCount         The number of Announce messages sent per channel.
     * @param[in]  aPeriod        The time between two successive MLE Announce transmissions (in milliseconds).
     * @param[in]  aAddress       The destination address.
     *
     * @retval kErrorNone    Successfully enqueued the Announce Begin message.
     * @retval kErrorNoBufs  Insufficient buffers to generate a Announce Begin message.
     */
    Error SendAnnounceBeginRequest(uint32_t            aChannelMask,
                                   uint8_t             aCount,
                                   uint16_t            aPeriod,
                                   const Ip6::Address &aAddress);

    /**
     * Sends an Energy Scan Query message.
     *
     * @param[in]  aChannelMask   The channel mask value.
     * @param[in]  aCount         The number of energy measurements per channel.
     * @param[in]  aPeriod        The time between energy measurements (milliseconds).
     * @param[in]  aScanDuration  The scan duration for each energy measurement (milliseconds).
     * @param[in]  aAddress       The IPv6 destination.
     * @param[in]  aCallback      Callback function called to report Energy Scan results.
     * @param[in]  aContext       A pointer to application-specific context.
     *
     * @retval kErrorNone     Successfully enqueued the Energy Scan Query message.
     * @retval kErrorNoBufs   Insufficient buffers to generate an Energy Scan Query message.
     */
    Error SendEnergyScanQuery(uint32_t             aChannelMask,
                              uint8_t              aCount,
                              uint16_t             aPeriod,
                              uint16_t             aScanDuration,
                              const Ip6::Address  &aAddress,
                              EnergyReportCallback aCallback,
                              void                *aContext);

    /**
     * Sends a PAN ID Query message.
     *
     * @param[in]  aPanId         The PAN ID to query.
     * @param[in]  aChannelMask   The channel mask value.
     * @param[in]  aAddress       The IPv6 destination.
     * @param[in]  aCallback      Callback function to report PAN ID conflicts.
     * @param[in]  aContext       A pointer to application-specific context.
     *
     * @retval kErrorNone    Successfully enqueued the PAN ID Query message.
     * @retval kErrorNoBufs  Insufficient buffers to generate a PAN ID Query message.
     */
    Error SendPanIdQuery(uint16_t              aPanId,
                         uint32_t              aChannelMask,
                         const Ip6::Address   &aAddress,
                         PanIdConflictCallback aCallback,
                         void                 *aContext);

private:
    static constexpr uint32_t kPetitionAttemptDelay = 5;  // COMM_PET_ATTEMPT_DELAY (seconds)
    static constexpr uint8_t  kPetitionRetryCount   = 2;  // COMM_PET_RETRY_COUNT
    static constexpr uint32_t kPetitionRetryDelay   = 1;  // COMM_PET_RETRY_DELAY (seconds)
    static constexpr uint32_t kKeepAliveTimeout     = 50; // TIMEOUT_COMM_PET (seconds)
    static constexpr uint32_t kRemoveJoinerDelay    = 20; // Delay to remove successfully joined joiner

    static constexpr uint16_t kMaxJoinerEntries = OPENTHREAD_CONFIG_COMMISSIONER_MAX_JOINER_ENTRIES;

    static constexpr uint32_t kJoinerSessionTimeoutMillis =
        1000 * OPENTHREAD_CONFIG_COMMISSIONER_JOINER_SESSION_TIMEOUT; // Expiration time for active Joiner session

    static constexpr uint8_t kMaxEnergyScanResults = OPENTHREAD_CONFIG_TMF_ENERGY_SCAN_MAX_RESULTS;

    enum ResignMode : uint8_t
    {
        kSendKeepAliveToResign,
        kDoNotSendKeepAlive,
    };

    struct Joiner
    {
        enum Type : uint8_t
        {
            kTypeUnused = 0, // Need to be 0 to ensure `memset()` clears all `Joiners`
            kTypeAny,
            kTypeEui64,
            kTypeDiscerner,
        };

        TimeMilli mExpirationTime;

        union
        {
            Mac::ExtAddress mEui64;
            JoinerDiscerner mDiscerner;
        } mSharedId;

        JoinerPskd      mPskd;
        Type            mType;
        uint16_t        mAssignedPanId;       // kNoAssignedPanId unless group-assigned at AddJoiner() time
        Mac::ExtAddress mLastChildExtAddress; // Set once this Joiner attaches; all-zero until then

        void CopyToJoinerInfo(otJoinerInfo &aJoiner) const;
    };

    // EUI-64 -> Group ID mapping - the preconfigured "Group Registry" (design doc §4.1).
    // Kept separate from `mJoiners[]`: "who's allowed to join with what credential" vs.
    // "which group they're pre-assigned to" are independently managed.
    struct GroupMembership
    {
        Mac::ExtAddress mEui64;
        uint8_t         mGroupId; // kUnboundGroupId means this slot is unused
    };

    static constexpr uint16_t kMaxGroupEntries = 32;

    Error   Stop(ResignMode aResignMode);
    Joiner *GetUnusedJoinerEntry(void);
    Joiner *FindJoinerEntry(const Mac::ExtAddress *aEui64);
    Joiner *FindJoinerEntry(const JoinerDiscerner &aDiscerner);
    Joiner *FindBestMatchingJoinerEntry(const Mac::ExtAddress &aReceivedJoinerId);
    void    RemoveJoinerEntry(Joiner &aJoiner);

    Error AddJoiner(const Mac::ExtAddress *aEui64,
                    const JoinerDiscerner *aDiscerner,
                    const char            *aPskd,
                    uint32_t               aTimeout);
    Error RemoveJoiner(const Mac::ExtAddress *aEui64, const JoinerDiscerner *aDiscerner, uint32_t aDelay);
    void  RemoveJoiner(Joiner &aJoiner, uint32_t aDelay);

    GroupMembership *FindGroupMembership(const Mac::ExtAddress &aEui64);
    GroupMembership *GetUnusedGroupMembership(void);
    uint8_t          FindGroupId(const Mac::ExtAddress &aEui64) const;

    // Resolves (and stores on `aJoiner`) the PAN ID a just-(re)added EUI-64 Joiner should
    // use: its group's bound PAN (allocating one if this is the group's first member), or
    // `kNoAssignedPanId` if it's not in the Group Registry (today's round-robin fallback,
    // unchanged). Force-detaches `aJoiner` if it was already assigned a *different* PAN.
    Error ResolveJoinerPanId(Joiner &aJoiner, const Mac::ExtAddress &aEui64);

    // Evicts `aJoiner`'s last-known attached child (if any) from the child table so it
    // rediscovers and reattaches on its own. Pure eviction - see design doc §10.4 for the
    // dataset-propagation dependency this does not itself resolve.
    void ForceDetachIfAttached(Joiner &aJoiner);

    void HandleTimer(void);
    void HandleJoinerExpirationTimer(void);

    DeclareTmfResponseHandlerIn(Commissioner, HandleMgmtCommissionerSetResponse);
    DeclareTmfResponseHandlerIn(Commissioner, HandleMgmtCommissionerGetResponse);
    DeclareTmfResponseHandlerIn(Commissioner, HandleLeaderPetitionResponse);
    DeclareTmfResponseHandlerIn(Commissioner, HandleLeaderKeepAliveResponse);

    static void HandleSecureAgentConnectEvent(Dtls::Session::ConnectEvent aEvent, void *aContext);
    void        HandleSecureAgentConnectEvent(Dtls::Session::ConnectEvent aEvent);

    template <Uri kUri> void HandleTmf(Coap::Msg &aMsg);

    void HandleRelayReceive(Coap::Message &aMessage, const Ip6::MessageInfo &aMessageInfo);

    void HandleJoinerSessionTimer(void);

    void SendJoinFinalizeResponse(const Coap::Message &aRequest, StateTlv::State aState);

    static Error SendRelayTransmit(void *aContext, Message &aMessage, const Ip6::MessageInfo &aMessageInfo);
    Error        SendRelayTransmit(Message &aMessage, const Ip6::MessageInfo &aMessageInfo);

    void  ComputeBloomFilter(SteeringData &aSteeringData) const;
    void  SendCommissionerSet(void);
    Error SendPetition(void);
    void  SendKeepAlive(void);
    void  SendKeepAlive(uint16_t aSessionId);

    void SetState(State aState);
    void SignalJoinerEvent(JoinerEvent aEvent, const Joiner *aJoiner) const;
    void LogJoinerEntry(const char *aAction, const Joiner &aJoiner) const;

    static const char *StateToString(State aState);

    using JoinerExpirationTimer = TimerMilliIn<Commissioner, &Commissioner::HandleJoinerExpirationTimer>;
    using CommissionerTimer     = TimerMilliIn<Commissioner, &Commissioner::HandleTimer>;
    using JoinerSessionTimer    = TimerMilliIn<Commissioner, &Commissioner::HandleJoinerSessionTimer>;

    Joiner                          mJoiners[kMaxJoinerEntries];
    GroupMembership                 mGroupRegistry[kMaxGroupEntries];
    Joiner                         *mActiveJoiner;
    Ip6::InterfaceIdentifier        mJoinerIid;
    uint16_t                        mJoinerPort;
    uint16_t                        mJoinerRloc;
    uint16_t                        mSessionId;
    uint8_t                         mTransmitAttempts;
    State                           mState;
    JoinerExpirationTimer           mJoinerExpirationTimer;
    CommissionerTimer               mTimer;
    JoinerSessionTimer              mJoinerSessionTimer;
    Ip6::Netif::UnicastAddress      mCommissionerAloc;
    ProvisioningUrlTlv::StringType  mProvisioningUrl;
    CommissionerIdTlv::StringType   mCommissionerId;
    Callback<StateCallback>         mStateCallback;
    Callback<JoinerCallback>        mJoinerCallback;
    Callback<EnergyReportCallback>  mEnergyReportCallback;
    Callback<PanIdConflictCallback> mPanIdConflictCallback;
};

DeclareTmfHandler(Commissioner, kUriDatasetChanged);
DeclareTmfHandler(Commissioner, kUriRelayRx);
DeclareTmfHandler(Commissioner, kUriJoinerFinalize);
DeclareTmfHandler(Commissioner, kUriEnergyReport);
DeclareTmfHandler(Commissioner, kUriPanIdConflict);

} // namespace MeshCoP

DefineMapEnum(otCommissionerState, MeshCoP::Commissioner::State);
DefineMapEnum(otCommissionerJoinerEvent, MeshCoP::Commissioner::JoinerEvent);

} // namespace ot

#endif // OPENTHREAD_FTD && OPENTHREAD_CONFIG_COMMISSIONER_ENABLE

#endif // OT_CORE_MESHCOP_COMMISSIONER_HPP_
