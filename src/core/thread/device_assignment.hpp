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
 *   This file includes helpers to look up entries of the Multi-PAN PAN ID assignment pool.
 */

#ifndef OT_CORE_THREAD_DEVICE_ASSIGNMENT_HPP_
#define OT_CORE_THREAD_DEVICE_ASSIGNMENT_HPP_

#include "openthread-core-config.h"

#include <stdint.h>

#include "thread/pan_id_assignment.hpp"

namespace ot {

/**
 * Finds the pool entry for a given PAN ID.
 *
 * @param[in] aPool      The pool.
 * @param[in] aPoolSize  The number of entries in @p aPool.
 * @param[in] aPanId     The PAN ID to look up.
 *
 * @returns A pointer to the matching entry, or `nullptr` if none.
 */
inline const PanIdAssignment *FindPanIdAssignment(const PanIdAssignment *aPool, uint8_t aPoolSize, uint16_t aPanId)
{
    const PanIdAssignment *rval = nullptr;

    for (uint8_t i = 0; i < aPoolSize; i++)
    {
        if (aPool[i].mPanId == aPanId)
        {
            rval = &aPool[i];
            break;
        }
    }

    return rval;
}

/**
 * Finds the pool entry already bound to a given (non-zero) Commissioner Group ID, if any.
 *
 * Used to reuse a group's already-allocated PAN and Network Key for every member after the first.
 *
 * @param[in] aPool      The pool.
 * @param[in] aPoolSize  The number of entries in @p aPool.
 * @param[in] aGroupId   The Group ID to look up.
 *
 * @returns A pointer to the bound entry, or `nullptr` if none.
 */
inline const PanIdAssignment *FindGroupBinding(const PanIdAssignment *aPool, uint8_t aPoolSize, uint8_t aGroupId)
{
    const PanIdAssignment *rval = nullptr;

    for (uint8_t i = 0; (aGroupId != kUnboundGroupId) && (i < aPoolSize); i++)
    {
        if (aPool[i].mGroupId == aGroupId)
        {
            rval = &aPool[i];
            break;
        }
    }

    return rval;
}

} // namespace ot

#endif // OT_CORE_THREAD_DEVICE_ASSIGNMENT_HPP_
