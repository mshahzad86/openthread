/*
 *  Copyright (c) 2024, The OpenThread Authors.
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
 *   This file includes compile-time configurations for Multi-PAN.
 */

#ifndef OT_CORE_CONFIG_MULTIPAN_H_
#define OT_CORE_CONFIG_MULTIPAN_H_

#include <stdint.h>

/**
 * @def OPENTHREAD_CONFIG_MULTIPLE_PAN_MAX_KEYS
 *
 * The maximum number of PAN keys supported.
 *
 */
#ifndef OPENTHREAD_CONFIG_MULTIPLE_PAN_MAX_KEYS
#define OPENTHREAD_CONFIG_MULTIPLE_PAN_MAX_KEYS 64
#endif

#ifdef __cplusplus
namespace ot {
static constexpr uint16_t kMaxPanKeys = OPENTHREAD_CONFIG_MULTIPLE_PAN_MAX_KEYS;
}
#else
/** 
 * Maximum number of PAN key entries supported. 
 */
#define kMaxPanKeys OPENTHREAD_CONFIG_MULTIPLE_PAN_MAX_KEYS
#endif

#endif // OT_CORE_CONFIG_MULTIPAN_H_
