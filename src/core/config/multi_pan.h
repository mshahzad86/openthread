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
 *   This file includes compile-time configurations for Multi-PAN (multiple Thread networks on a single radio).
 */

#ifndef OT_CORE_CONFIG_MULTI_PAN_H_
#define OT_CORE_CONFIG_MULTI_PAN_H_

/**
 * @addtogroup config-multi-pan
 *
 * @brief
 *   This module includes configuration variables for Multi-PAN.
 *
 * Multi-PAN lets a router serve devices on several PANs (each with its own Network Key) at the same time. The extra
 * PAN IDs and keys come from the PAN ID and PAN Key lists in the Operational Dataset.
 *
 * This is unrelated to `OPENTHREAD_CONFIG_MULTIPAN_RCP_ENABLE` (several host stacks sharing one RCP).
 *
 * @{
 */

/**
 * @def OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
 *
 * Define as 1 to enable Multi-PAN support.
 */
#ifndef OPENTHREAD_CONFIG_MULTI_PAN_ENABLE
#define OPENTHREAD_CONFIG_MULTI_PAN_ENABLE 0
#endif

/**
 * @def OPENTHREAD_CONFIG_MULTI_PAN_MAX_PANS
 *
 * The maximum number of PAN entries in the per-PAN key map (including the router's own PAN).
 *
 * This value is part of the platform and Spinel contract (`OT_RADIO_MULTI_PAN_MAX_KEYS`), so it MUST match the RCP.
 */
#ifndef OPENTHREAD_CONFIG_MULTI_PAN_MAX_PANS
#define OPENTHREAD_CONFIG_MULTI_PAN_MAX_PANS 64
#endif

/**
 * @def OPENTHREAD_CONFIG_MULTI_PAN_DEBUG_LOGS_ENABLE
 *
 * Define as 1 to emit the Multi-PAN debug logs (PAN allocation, framer and commissioning decisions) at warning level.
 *
 * These logs are read by the Multi-PAN experiment tooling, so their text is kept stable.
 */
#ifndef OPENTHREAD_CONFIG_MULTI_PAN_DEBUG_LOGS_ENABLE
#define OPENTHREAD_CONFIG_MULTI_PAN_DEBUG_LOGS_ENABLE 0
#endif

/**
 * @}
 */

#endif // OT_CORE_CONFIG_MULTI_PAN_H_
