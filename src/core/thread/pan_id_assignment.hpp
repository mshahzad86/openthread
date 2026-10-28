/*
 *  Copyright (c) 2026, The OpenThread Authors.
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
 *   This file defines the Multi-PAN PAN ID assignment pool entry.
 */

#ifndef OT_CORE_THREAD_PAN_ID_ASSIGNMENT_HPP_
#define OT_CORE_THREAD_PAN_ID_ASSIGNMENT_HPP_

#include "openthread-core-config.h"

#include <stdint.h>

/**
 * Logs a Multi-PAN debug message (PAN allocation, framer and commissioning decisions) at warning level.
 *
 * Only emits when `OPENTHREAD_CONFIG_MULTI_PAN_DEBUG_LOGS_ENABLE` is set. The arguments are always evaluated by the
 * compiler (and then discarded) so variables used only for these logs do not trigger unused-variable warnings.
 */
#define LogMultiPan(...)                                   \
    do                                                     \
    {                                                      \
        if (OPENTHREAD_CONFIG_MULTI_PAN_DEBUG_LOGS_ENABLE) \
        {                                                  \
            LogWarn(__VA_ARGS__);                          \
        }                                                  \
    } while (false)

namespace ot {

static constexpr uint8_t kNetworkKeySize = 16; ///< Size of a Network Key in a pool entry (bytes).

/**
 * Reserved Group ID meaning "unbound / available for round-robin", i.e. a pool entry that no Commissioner Group
 * Registry mapping currently claims. Group IDs given to the Commissioner's group commands must be non-zero.
 */
static constexpr uint8_t kUnboundGroupId = 0;

/**
 * Represents one entry of the Multi-PAN PAN ID assignment pool.
 */
struct PanIdAssignment
{
    uint16_t mPanId;                       ///< The PAN ID.
    uint8_t  mNetworkKey[kNetworkKeySize]; ///< The Network Key of the PAN.
    uint8_t  mGroupId;                     ///< `kUnboundGroupId` unless bound to a Commissioner group.
};

/**
 * Tells the PAN allocator that a PAN is reserved (e.g. held by a pending Commissioner Joiner entry) and must be
 * skipped even though no child is attached on it yet.
 *
 * @param[in] aContext  The context given to the allocator.
 * @param[in] aPanId    The candidate PAN ID.
 *
 * @retval TRUE   @p aPanId is reserved.
 * @retval FALSE  @p aPanId is not reserved.
 */
typedef bool (*PanIdReservedFn)(const void *aContext, uint16_t aPanId);

} // namespace ot

#endif // OT_CORE_THREAD_PAN_ID_ASSIGNMENT_HPP_
