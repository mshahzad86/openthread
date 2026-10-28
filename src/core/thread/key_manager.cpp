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
 *   This file implements Thread security material generation.
 */

#include "key_manager.hpp"

#include "crypto/hkdf_sha256.hpp"
#include "crypto/storage.hpp"
#include "instance/instance.hpp"
#include "thread/device_assignment.hpp"

namespace ot {

RegisterLogModule("KeyManager");

const uint8_t KeyManager::kThreadString[] = {
    'T', 'h', 'r', 'e', 'a', 'd',
};

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
const uint8_t KeyManager::kHkdfExtractSaltString[] = {'T', 'h', 'r', 'e', 'a', 'd', 'S', 'e', 'q', 'u', 'e', 'n',
                                                      'c', 'e', 'M', 'a', 's', 't', 'e', 'r', 'K', 'e', 'y'};

const uint8_t KeyManager::kTrelInfoString[] = {'T', 'h', 'r', 'e', 'a', 'd', 'O', 'v', 'e',
                                               'r', 'I', 'n', 'f', 'r', 'a', 'K', 'e', 'y'};
#endif

//---------------------------------------------------------------------------------------------------------------------
// SecurityPolicy

void SecurityPolicy::SetToDefault(void)
{
    Clear();
    mRotationTime = kDefaultKeyRotationTime;
    SetToDefaultFlags();
}

void SecurityPolicy::SetToDefaultFlags(void)
{
    mObtainNetworkKeyEnabled        = true;
    mNativeCommissioningEnabled     = true;
    mRoutersEnabled                 = true;
    mExternalCommissioningEnabled   = true;
    mCommercialCommissioningEnabled = false;
    mAutonomousEnrollmentEnabled    = false;
    mNetworkKeyProvisioningEnabled  = false;
    mTobleLinkEnabled               = true;
    mNonCcmRoutersEnabled           = false;
    mVersionThresholdForRouting     = 0;
}

void SecurityPolicy::SetFlags(const uint8_t *aFlags, uint8_t aFlagsLength)
{
    OT_ASSERT(aFlagsLength > 0);

    SetToDefaultFlags();

    mObtainNetworkKeyEnabled        = aFlags[0] & kObtainNetworkKeyMask;
    mNativeCommissioningEnabled     = aFlags[0] & kNativeCommissioningMask;
    mRoutersEnabled                 = aFlags[0] & kRoutersMask;
    mExternalCommissioningEnabled   = aFlags[0] & kExternalCommissioningMask;
    mCommercialCommissioningEnabled = (aFlags[0] & kCommercialCommissioningMask) == 0;
    mAutonomousEnrollmentEnabled    = (aFlags[0] & kAutonomousEnrollmentMask) == 0;
    mNetworkKeyProvisioningEnabled  = (aFlags[0] & kNetworkKeyProvisioningMask) == 0;

    VerifyOrExit(aFlagsLength > sizeof(aFlags[0]));
    mTobleLinkEnabled           = aFlags[1] & kTobleLinkMask;
    mNonCcmRoutersEnabled       = (aFlags[1] & kNonCcmRoutersMask) == 0;
    mVersionThresholdForRouting = aFlags[1] & kVersionThresholdForRoutingMask;

exit:
    return;
}

void SecurityPolicy::GetFlags(uint8_t *aFlags, uint8_t aFlagsLength) const
{
    OT_ASSERT(aFlagsLength > 0);

    memset(aFlags, 0, aFlagsLength);

    if (mObtainNetworkKeyEnabled)
    {
        aFlags[0] |= kObtainNetworkKeyMask;
    }

    if (mNativeCommissioningEnabled)
    {
        aFlags[0] |= kNativeCommissioningMask;
    }

    if (mRoutersEnabled)
    {
        aFlags[0] |= kRoutersMask;
    }

    if (mExternalCommissioningEnabled)
    {
        aFlags[0] |= kExternalCommissioningMask;
    }

    if (!mCommercialCommissioningEnabled)
    {
        aFlags[0] |= kCommercialCommissioningMask;
    }

    if (!mAutonomousEnrollmentEnabled)
    {
        aFlags[0] |= kAutonomousEnrollmentMask;
    }

    if (!mNetworkKeyProvisioningEnabled)
    {
        aFlags[0] |= kNetworkKeyProvisioningMask;
    }

    VerifyOrExit(aFlagsLength > sizeof(aFlags[0]));

    if (mTobleLinkEnabled)
    {
        aFlags[1] |= kTobleLinkMask;
    }

    if (!mNonCcmRoutersEnabled)
    {
        aFlags[1] |= kNonCcmRoutersMask;
    }

    aFlags[1] |= kReservedMask;
    aFlags[1] |= mVersionThresholdForRouting;

exit:
    return;
}

//---------------------------------------------------------------------------------------------------------------------
// KeyManager

KeyManager::KeyManager(Instance &aInstance)
    : InstanceLocator(aInstance)
    , mKeySequence(0)
    , mMleFrameCounter(0)
    , mStoredMacFrameCounter(0)
    , mStoredMleFrameCounter(0)
    , mHoursSinceKeyRotation(0)
    , mKeySwitchGuardTime(kDefaultKeySwitchGuardTime)
    , mKeySwitchGuardTimer(0)
    , mKeyRotationTimer(aInstance)
    , mKekFrameCounter(0)
    , mIsPskcSet(false)
    , mIsKekSet(false)
{
    otPlatCryptoInit();

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    mPanIdCount    = 0;
    mPanKeyCount   = 0;
    mPanIdPoolSize = 0;
    mNextPoolIndex = 0;
    ClearAllBytes(mPanIds);
    ClearAllBytes(mPanKeys);
    ClearAllBytes(mPanIdPool);
#endif

#if OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE
    mNetworkKeyRef = Crypto::Storage::kInvalidKeyRef;
    mPskcRef       = Crypto::Storage::kInvalidKeyRef;
#else
    IgnoreError(mNetworkKey.GenerateRandom());
    mPskc.Clear();
#endif

    mMacFrameCounters.Reset();
}

void KeyManager::Init(void)
{
#if OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE
    NetworkKey networkKey;

    IgnoreError(networkKey.GenerateRandom());
    StoreNetworkKey(networkKey, /* aOverWriteExisting */ false);
#endif
}

void KeyManager::Start(void)
{
    mKeySwitchGuardTimer = 0;
    ResetKeyRotationTimer();
}

void KeyManager::Stop(void) { mKeyRotationTimer.Stop(); }

void KeyManager::SetPskc(const Pskc &aPskc)
{
#if OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE
    if (Crypto::Storage::IsKeyRefValid(mPskcRef))
    {
        Pskc pskc;

        GetPskc(pskc);
        VerifyOrExit(aPskc != pskc, Get<Notifier>().SignalIfFirst(kEventPskcChanged));
    }

    StorePskc(aPskc);
    Get<Notifier>().Signal(kEventPskcChanged);
#else
    SuccessOrExit(Get<Notifier>().Update(mPskc, aPskc, kEventPskcChanged));
#endif

exit:
    mIsPskcSet = true;
}

void KeyManager::ResetFrameCounters(void)
{
    Router *parent;

    // reset parent frame counters
    parent = &Get<Mle::Mle>().GetParent();
    parent->SetKeySequence(0);
    parent->GetLinkFrameCounters().Reset();
    parent->SetLinkAckFrameCounter(0);
    parent->SetMleFrameCounter(0);

#if OPENTHREAD_FTD
    // reset router frame counters
    for (Router &router : Get<RouterTable>())
    {
        router.SetKeySequence(0);
        router.GetLinkFrameCounters().Reset();
        router.SetLinkAckFrameCounter(0);
        router.SetMleFrameCounter(0);
    }

    // reset child frame counters
    for (Child &child : Get<ChildTable>().Iterate(Child::kInStateAnyExceptInvalid))
    {
        child.SetKeySequence(0);
        child.GetLinkFrameCounters().Reset();
        child.SetLinkAckFrameCounter(0);
        child.SetMleFrameCounter(0);
    }
#endif
}

void KeyManager::SetNetworkKey(const NetworkKey &aNetworkKey)
{
#if OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE
    if (Crypto::Storage::IsKeyRefValid(mNetworkKeyRef))
    {
        NetworkKey networkKey;

        GetNetworkKey(networkKey);
        VerifyOrExit(networkKey != aNetworkKey, Get<Notifier>().SignalIfFirst(kEventNetworkKeyChanged));
    }

    StoreNetworkKey(aNetworkKey, /* aOverWriteExisting */ true);
    Get<Notifier>().Signal(kEventNetworkKeyChanged);
#else
    SuccessOrExit(Get<Notifier>().Update(mNetworkKey, aNetworkKey, kEventNetworkKeyChanged));
#endif

    Get<Notifier>().Signal(kEventThreadKeySeqCounterChanged);

    mKeySequence = 0;
    UpdateKeyMaterial();
    ResetFrameCounters();

exit:
    return;
}

void KeyManager::ComputeKeys(uint32_t aKeySequence, HashKeys &aHashKeys) const
{
    Crypto::HmacSha256 hmac;
    uint8_t            keySequenceBytes[sizeof(uint32_t)];
    Crypto::Key        cryptoKey;

#if OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE
    cryptoKey.SetAsKeyRef(mNetworkKeyRef);
#else
    cryptoKey.Set(mNetworkKey.m8, NetworkKey::kSize);
#endif

    hmac.Start(cryptoKey);

    BigEndian::WriteUint32(aKeySequence, keySequenceBytes);
    hmac.Update(keySequenceBytes);
    hmac.Update(kThreadString);

    hmac.Finish(aHashKeys.mHash);
}

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
void KeyManager::ComputeTrelKey(uint32_t aKeySequence, Mac::Key &aKey) const
{
    Crypto::HkdfSha256 hkdf;
    uint8_t            salt[sizeof(uint32_t) + sizeof(kHkdfExtractSaltString)];
    Crypto::Key        cryptoKey;

#if OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE
    cryptoKey.SetAsKeyRef(mNetworkKeyRef);
#else
    cryptoKey.Set(mNetworkKey.m8, NetworkKey::kSize);
#endif

    BigEndian::WriteUint32(aKeySequence, salt);
    memcpy(salt + sizeof(uint32_t), kHkdfExtractSaltString, sizeof(kHkdfExtractSaltString));

    hkdf.Extract(salt, sizeof(salt), cryptoKey);
    hkdf.Expand(kTrelInfoString, sizeof(kTrelInfoString), aKey.m8, Mac::Key::kSize);
}
#endif

void KeyManager::UpdateKeyMaterial(void)
{
    HashKeys hashKeys;

    ComputeKeys(mKeySequence, hashKeys);

    mMleKey.SetFrom(hashKeys.GetMleKey());

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    {
        HashKeys prevHashKeys;
        HashKeys nextHashKeys;

        ComputeKeys(mKeySequence - 1, prevHashKeys);
        ComputeKeys(mKeySequence + 1, nextHashKeys);

        Get<Mac::SubMac>().SetMode1MacKeys(Mac::DetermineKeyIndexFor(mKeySequence), prevHashKeys.GetMacKey(),
                                           hashKeys.GetMacKey(), nextHashKeys.GetMacKey());
    }
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
    {
        Mac::Key key;

        ComputeTrelKey(mKeySequence, key);
        mTrelKey.SetFrom(key);
    }
#endif

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    UpdatePanKeyMaterial();
#endif
}

#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE

void KeyManager::ComputeKeys(const NetworkKey &aNetworkKey, uint32_t aKeySequence, HashKeys &aHashKeys) const
{
    Crypto::HmacSha256 hmac;
    uint8_t            keySequenceBytes[sizeof(uint32_t)];
    Crypto::Key        cryptoKey;

    cryptoKey.Set(aNetworkKey.m8, NetworkKey::kSize);

    hmac.Start(cryptoKey);

    BigEndian::WriteUint32(aKeySequence, keySequenceBytes);
    hmac.Update(keySequenceBytes);
    hmac.Update(kThreadString);

    hmac.Finish(aHashKeys.mHash);
}

uint8_t KeyManager::GetNumKeyedPans(void) const
{
    // Entry 0 of the per-PAN MAC key map is the router's own PAN,
    // so at most `kMaxPans - 1` listed PANs get keys.

    return Min<uint8_t>(Min(mPanIdCount, mPanKeyCount), kMaxPans - 1);
}

int16_t KeyManager::FindKeyedPanIndex(Mac::PanId aPanId) const
{
    int16_t index = -1;

    for (uint8_t i = 0; i < GetNumKeyedPans(); i++)
    {
        if (mPanIds[i] == aPanId)
        {
            index = i;
            break;
        }
    }

    return index;
}

void KeyManager::UpdatePanKeyMaterial(void)
{
    // Derives the MLE key and the previous/current/next MAC keys of
    // every listed PAN. The router's own PAN is entry 0 of the MAC
    // key map. Every slot past the last PAN is cleared ("clean
    // slate"), so no key of a PAN removed from the list survives.

    uint8_t numPans = GetNumKeyedPans();

    for (uint8_t i = 0; i < numPans; i++)
    {
        HashKeys hashKeys;

        ComputeKeys(mPanKeys[i], mKeySequence, hashKeys);
        mPanMleKeys[i].SetFrom(hashKeys.GetMleKey());
    }

    for (uint8_t i = numPans; i < kMaxPans; i++)
    {
        mPanMleKeys[i].Clear();
    }

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    {
        Mac::SubMac &subMac   = Get<Mac::SubMac>();
        uint8_t      keyIndex = Mac::DetermineKeyIndexFor(mKeySequence);

        {
            HashKeys prevHashKeys;
            HashKeys curHashKeys;
            HashKeys nextHashKeys;

            ComputeKeys(mKeySequence - 1, prevHashKeys);
            ComputeKeys(mKeySequence, curHashKeys);
            ComputeKeys(mKeySequence + 1, nextHashKeys);

            subMac.SetPanMode1MacKeys(0, Get<Mac::Mac>().GetPanId(), keyIndex, prevHashKeys.GetMacKey(),
                                      curHashKeys.GetMacKey(), nextHashKeys.GetMacKey());
        }

        for (uint8_t i = 0; i < numPans; i++)
        {
            HashKeys prevHashKeys;
            HashKeys curHashKeys;
            HashKeys nextHashKeys;

            ComputeKeys(mPanKeys[i], mKeySequence - 1, prevHashKeys);
            ComputeKeys(mPanKeys[i], mKeySequence, curHashKeys);
            ComputeKeys(mPanKeys[i], mKeySequence + 1, nextHashKeys);

            subMac.SetPanMode1MacKeys(i + 1, mPanIds[i], keyIndex, prevHashKeys.GetMacKey(), curHashKeys.GetMacKey(),
                                      nextHashKeys.GetMacKey());
        }

        subMac.ClearPanMode1MacKeys(numPans + 1);
        subMac.CommitPanMode1MacKeys();
    }
#endif
}

void KeyManager::SetPanIds(const otPanIdList &aPanIds)
{
    mPanIdCount = Min<uint8_t>(aPanIds.mCount, kMaxPans);

    for (uint8_t i = 0; i < mPanIdCount; i++)
    {
        mPanIds[i] = aPanIds.mPanIds[i];
    }

    if (aPanIds.mCount > mPanIdCount)
    {
        LogWarn("PAN ID list truncated to %u entries", mPanIdCount);
    }

    // Only the per-PAN key map changes. The router's own keys are not
    // set again, since radios reset their frame counter when they are.
    CheckForKeyRotation();
    UpdatePanKeyMaterial();
    Get<Mac::Mac>().UpdateMultiPanIds();
}

void KeyManager::SetPanKeys(const otPanKeyList &aPanKeys)
{
    mPanKeyCount = Min<uint8_t>(aPanKeys.mCount, kMaxPans);

    for (uint8_t i = 0; i < mPanKeyCount; i++)
    {
        memcpy(mPanKeys[i].m8, aPanKeys.mPanKeys[i].m8, NetworkKey::kSize);
    }

    CheckForKeyRotation();
    UpdatePanKeyMaterial();

    // PAN keys are not part of the Dataset, so a dataset apply does
    // not follow a key change. Rebuild the pool so no stale key is
    // handed to a joiner.
    BuildPanIdPool();
}

bool KeyManager::IsPanIdInList(Mac::PanId aPanId) const
{
    bool found = false;

    for (uint8_t i = 0; i < mPanIdCount; i++)
    {
        if (mPanIds[i] == aPanId)
        {
            found = true;
            break;
        }
    }

    return found;
}

const Mle::KeyMaterial *KeyManager::GetMleKeyForPanId(Mac::PanId aPanId) const
{
    const Mle::KeyMaterial *key = nullptr;
    int16_t                 index;

    if (aPanId == Get<Mac::Mac>().GetPanId())
    {
        ExitNow(key = &mMleKey);
    }

    index = FindKeyedPanIndex(aPanId);
    VerifyOrExit(index >= 0);
    key = &mPanMleKeys[index];

exit:
    return key;
}

const Mle::KeyMaterial *KeyManager::GetTemporaryMleKeyForPanId(uint32_t aKeySequence, Mac::PanId aPanId)
{
    const Mle::KeyMaterial *key = nullptr;
    int16_t                 index;
    HashKeys                hashKeys;

    if (aPanId == Get<Mac::Mac>().GetPanId())
    {
        ExitNow(key = &GetTemporaryMleKey(aKeySequence));
    }

    index = FindKeyedPanIndex(aPanId);
    VerifyOrExit(index >= 0);

    ComputeKeys(mPanKeys[index], aKeySequence, hashKeys);
    mTemporaryMleKey.SetFrom(hashKeys.GetMleKey());
    key = &mTemporaryMleKey;

exit:
    return key;
}

void KeyManager::BuildPanIdPool(void)
{
    uint8_t    count = Min<uint8_t>(Min(mPanIdCount, mPanKeyCount), kMaxPans);
    NetworkKey networkKey;

    mPanIdPoolSize = 0;

    for (uint8_t i = 0; i < count; i++)
    {
        PanIdAssignment &entry = mPanIdPool[mPanIdPoolSize++];

        entry.mPanId = mPanIds[i];
        memcpy(entry.mNetworkKey, mPanKeys[i].m8, NetworkKey::kSize);
        entry.mGroupId = kUnboundGroupId;
    }

    GetNetworkKey(networkKey);

    mPanIdPool[mPanIdPoolSize].mPanId = Get<Mac::Mac>().GetPanId();
    memcpy(mPanIdPool[mPanIdPoolSize].mNetworkKey, networkKey.m8, NetworkKey::kSize);
    mPanIdPool[mPanIdPoolSize].mGroupId = kUnboundGroupId;
    mPanIdPoolSize++;

    if (mNextPoolIndex >= mPanIdPoolSize)
    {
        mNextPoolIndex = 0;
    }

    LogMultiPan("PanIdPool built: %u entries (%u joiner PANs + router PAN 0x%04x last)", mPanIdPoolSize,
                mPanIdPoolSize - 1, mPanIdPool[mPanIdPoolSize - 1].mPanId);
}

const PanIdAssignment *KeyManager::FindGroupBinding(uint8_t aGroupId) const
{
    return ot::FindGroupBinding(mPanIdPool, mPanIdPoolSize, aGroupId);
}

Error KeyManager::BindPanIdToGroup(uint16_t aPanId, uint8_t aGroupId)
{
    Error error = kErrorNotFound;

    for (uint8_t i = 0; i < mPanIdPoolSize; i++)
    {
        if (mPanIdPool[i].mPanId == aPanId)
        {
            mPanIdPool[i].mGroupId = aGroupId;
            error                  = kErrorNone;
            break;
        }
    }

    return error;
}

#if OPENTHREAD_FTD
const PanIdAssignment *KeyManager::AllocateNextPanId(PanIdReservedFn aIsReserved, const void *aContext)
{
    const PanIdAssignment *rval = nullptr;

    for (uint8_t i = 0; i < mPanIdPoolSize; i++)
    {
        uint8_t                index     = (mNextPoolIndex + i) % mPanIdPoolSize;
        const PanIdAssignment &candidate = mPanIdPool[index];
        bool                   inUse     = false;

        for (Child &child : Get<ChildTable>().Iterate(Child::kInStateValidOrRestoring))
        {
            if (child.GetPanId() == candidate.mPanId)
            {
                inUse = true;
                break;
            }
        }

        inUse = inUse || (candidate.mGroupId != kUnboundGroupId) ||
                ((aIsReserved != nullptr) && aIsReserved(aContext, candidate.mPanId));

        if (!inUse)
        {
            mNextPoolIndex = (index + 1) % mPanIdPoolSize;
            rval           = &candidate;
            break;
        }
    }

    return rval;
}
#endif // OPENTHREAD_FTD

#endif // OPENTHREAD_CONFIG_MULTI_PAN_ENABLE

void KeyManager::SetCurrentKeySequence(uint32_t aKeySequence, KeySeqUpdateFlags aFlags)
{
    VerifyOrExit(aKeySequence != mKeySequence, Get<Notifier>().SignalIfFirst(kEventThreadKeySeqCounterChanged));

    if (aFlags & kApplySwitchGuard)
    {
        VerifyOrExit(mKeySwitchGuardTimer == 0);
    }

    // MAC frame counters are reset before updating keys. This order
    // safeguards against issues that can arise when the radio
    // platform handles TX security and counter assignment.  The
    // radio platform might prepare an enhanced ACK to a received
    // frame from an parallel (e.g., ISR) context, which consumes
    // a MAC frame counter value.
    //
    // Ideally, a call to `otPlatRadioSetMacKey()`, which sets the MAC
    // keys on the radio, should also reset the frame counter tracked
    // by the radio. However, if this is not implemented by the radio
    // platform, resetting the counter first ensures new keys always
    // start with a zero counter and avoids potential issue below.
    //
    // If the MAC key is updated before the frame counter is cleared,
    // the radio could receive and send an enhanced ACK between these
    // two actions, possibly using the new MAC key with a larger
    // (current) frame counter value. This could then prevent the
    // receiver from accepting subsequent transmissions after the
    // frame counter reset for a long time.
    //
    // While resetting counters first might briefly cause an enhanced
    // ACK to be sent with the old key and a zero counter (which might
    // be rejected by the receiver), this is a transient issue that
    // quickly resolves itself.

    SetAllMacFrameCounters(0, /* aSetIfLarger */ false);
    mMleFrameCounter = 0;

    mKeySequence = aKeySequence;
    UpdateKeyMaterial();

    ResetKeyRotationTimer();

    if (aFlags & kResetGuardTimer)
    {
        mKeySwitchGuardTimer = mKeySwitchGuardTime;
    }

    Get<Notifier>().Signal(kEventThreadKeySeqCounterChanged);

exit:
    return;
}

const Mle::KeyMaterial &KeyManager::GetTemporaryMleKey(uint32_t aKeySequence)
{
    HashKeys hashKeys;

    ComputeKeys(aKeySequence, hashKeys);
    mTemporaryMleKey.SetFrom(hashKeys.GetMleKey());

    return mTemporaryMleKey;
}

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
const Mac::KeyMaterial &KeyManager::GetTemporaryTrelMacKey(uint32_t aKeySequence)
{
    Mac::Key key;

    ComputeTrelKey(aKeySequence, key);
    mTemporaryTrelKey.SetFrom(key);

    return mTemporaryTrelKey;
}
#endif

void KeyManager::SetAllMacFrameCounters(uint32_t aFrameCounter, bool aSetIfLarger)
{
    mMacFrameCounters.SetAll(aFrameCounter);

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
    Get<Mac::SubMac>().SetFrameCounter(aFrameCounter, aSetIfLarger);
#else
    OT_UNUSED_VARIABLE(aSetIfLarger);
#endif
}

#if OPENTHREAD_CONFIG_RADIO_LINK_IEEE_802_15_4_ENABLE
void KeyManager::MacFrameCounterUsed(uint32_t aMacFrameCounter)
{
    // This is callback from `SubMac` to indicate that a frame
    // counter value is used for tx. We ensure to handle it
    // even if it is called out of order.

    VerifyOrExit(mMacFrameCounters.Get154() <= aMacFrameCounter);

    mMacFrameCounters.Set154(aMacFrameCounter + 1);

    if (mMacFrameCounters.Get154() >= mStoredMacFrameCounter)
    {
        Get<Mle::Mle>().Store();
    }

exit:
    return;
}
#else
void KeyManager::MacFrameCounterUsed(uint32_t) {}
#endif

#if OPENTHREAD_CONFIG_RADIO_LINK_TREL_ENABLE
void KeyManager::IncrementTrelMacFrameCounter(void)
{
    mMacFrameCounters.IncrementTrel();

    if (mMacFrameCounters.GetTrel() >= mStoredMacFrameCounter)
    {
        Get<Mle::Mle>().Store();
    }
}
#endif

void KeyManager::IncrementMleFrameCounter(void)
{
    mMleFrameCounter++;

    if (mMleFrameCounter >= mStoredMleFrameCounter)
    {
        Get<Mle::Mle>().Store();
    }
}

void KeyManager::SetKek(const Kek &aKek)
{
    mKek.SetFrom(aKek, /* aIsExportable */ true);
    mKekFrameCounter = 0;
    mIsKekSet        = true;
}

void KeyManager::ClearKek(void)
{
    mKek.Clear();
    mIsKekSet = false;
}

void KeyManager::SetSecurityPolicy(const SecurityPolicy &aSecurityPolicy)
{
    SecurityPolicy newPolicy = aSecurityPolicy;

    if (newPolicy.mRotationTime < SecurityPolicy::kMinKeyRotationTime)
    {
        newPolicy.mRotationTime = SecurityPolicy::kMinKeyRotationTime;
        LogNote("Key Rotation Time in SecurityPolicy is set to min allowed value of %u", newPolicy.mRotationTime);
    }

    if (newPolicy.mRotationTime != mSecurityPolicy.mRotationTime)
    {
        uint32_t newGuardTime = newPolicy.mRotationTime;

        // Calculations are done using a `uint32_t` variable to prevent
        // potential overflow.

        newGuardTime *= kKeySwitchGuardTimePercentage;
        newGuardTime /= 100;

        mKeySwitchGuardTime = static_cast<uint16_t>(newGuardTime);
    }

    IgnoreError(Get<Notifier>().Update(mSecurityPolicy, newPolicy, kEventSecurityPolicyChanged));

    CheckForKeyRotation();
}

void KeyManager::ResetKeyRotationTimer(void)
{
    mHoursSinceKeyRotation = 0;
    mKeyRotationTimer.Start(Time::kOneHourInMsec);
}

void KeyManager::HandleKeyRotationTimer(void)
{
    mKeyRotationTimer.Start(Time::kOneHourInMsec);

    mHoursSinceKeyRotation++;

    if (mKeySwitchGuardTimer > 0)
    {
        mKeySwitchGuardTimer--;
    }

    CheckForKeyRotation();
}

void KeyManager::CheckForKeyRotation(void)
{
    if (mHoursSinceKeyRotation >= mSecurityPolicy.mRotationTime)
    {
        SetCurrentKeySequence(mKeySequence + 1, kForceUpdate | kResetGuardTimer);
    }
}

void KeyManager::GetNetworkKey(NetworkKey &aNetworkKey) const
{
#if OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE
    if (Crypto::Storage::HasKey(mNetworkKeyRef))
    {
        size_t keyLen;

        SuccessOrAssert(Crypto::Storage::ReadKey(mNetworkKeyRef, aNetworkKey.m8, NetworkKey::kSize, keyLen));
        OT_ASSERT(keyLen == NetworkKey::kSize);
    }
    else
    {
        aNetworkKey.Clear();
    }
#else
    aNetworkKey = mNetworkKey;
#endif
}

void KeyManager::GetPskc(Pskc &aPskc) const
{
#if OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE
    if (Crypto::Storage::HasKey(mPskcRef))
    {
        size_t keyLen;

        SuccessOrAssert(Crypto::Storage::ReadKey(mPskcRef, aPskc.m8, Pskc::kSize, keyLen));
        OT_ASSERT(keyLen == Pskc::kSize);
    }
    else
    {
        aPskc.Clear();
    }
#else
    aPskc = mPskc;
#endif
}

#if OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE

void KeyManager::StoreNetworkKey(const NetworkKey &aNetworkKey, bool aOverWriteExisting)
{
    NetworkKeyRef keyRef;

    keyRef = Get<Crypto::Storage::KeyRefManager>().KeyRefFor(Crypto::Storage::KeyRefManager::kNetworkKey);

    if (!aOverWriteExisting)
    {
        // Check if there is already a network key stored in secure
        // storage. If stored, and we are not overwriting the existing
        // key, return without doing anything.

        if (Crypto::Storage::HasKey(keyRef))
        {
            ExitNow();
        }
    }

    Crypto::Storage::DestroyKey(keyRef);

    SuccessOrAssert(Crypto::Storage::SaveKey(keyRef, Crypto::Storage::kKeyTypeHmac,
                                             Crypto::Storage::kKeyAlgorithmHmacSha256,
                                             Crypto::Storage::kUsageSignHash | Crypto::Storage::kUsageExport,
                                             Crypto::Storage::kTypePersistent, aNetworkKey.m8, NetworkKey::kSize));

exit:
    if (mNetworkKeyRef != keyRef)
    {
        Crypto::Storage::DestroyKey(mNetworkKeyRef);
    }

    mNetworkKeyRef = keyRef;
}

void KeyManager::StorePskc(const Pskc &aPskc)
{
    PskcRef keyRef = Get<Crypto::Storage::KeyRefManager>().KeyRefFor(Crypto::Storage::KeyRefManager::kPskc);

    Crypto::Storage::DestroyKey(keyRef);

    SuccessOrAssert(Crypto::Storage::SaveKey(keyRef, Crypto::Storage::kKeyTypeRaw, Crypto::Storage::kKeyAlgorithmVendor,
                                             Crypto::Storage::kUsageExport, Crypto::Storage::kTypePersistent, aPskc.m8,
                                             Pskc::kSize));

    if (mPskcRef != keyRef)
    {
        Crypto::Storage::DestroyKey(mPskcRef);
    }

    mPskcRef = keyRef;
}

void KeyManager::SetPskcRef(PskcRef aKeyRef)
{
    VerifyOrExit(mPskcRef != aKeyRef, Get<Notifier>().SignalIfFirst(kEventPskcChanged));

    Crypto::Storage::DestroyKey(mPskcRef);

    mPskcRef = aKeyRef;
    Get<Notifier>().Signal(kEventPskcChanged);

exit:
    mIsPskcSet = true;
}

void KeyManager::SetNetworkKeyRef(otNetworkKeyRef aKeyRef)
{
    VerifyOrExit(mNetworkKeyRef != aKeyRef, Get<Notifier>().SignalIfFirst(kEventNetworkKeyChanged));

    Crypto::Storage::DestroyKey(mNetworkKeyRef);

    mNetworkKeyRef = aKeyRef;
    Get<Notifier>().Signal(kEventNetworkKeyChanged);
    Get<Notifier>().Signal(kEventThreadKeySeqCounterChanged);
    mKeySequence = 0;
    UpdateKeyMaterial();
    ResetFrameCounters();

exit:
    return;
}

void KeyManager::DestroyTemporaryKeys(void)
{
    mMleKey.Clear();
#if OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
    for (Mle::KeyMaterial &panMleKey : mPanMleKeys)
    {
        panMleKey.Clear();
    }
#endif
    mKek.Clear();
    mIsKekSet = false;
    Get<Mac::SubMac>().ClearMacKeys();
}

void KeyManager::DestroyPersistentKeys(void) { Get<Crypto::Storage::KeyRefManager>().DestroyPersistentKeys(); }

#endif // OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE

} // namespace ot
