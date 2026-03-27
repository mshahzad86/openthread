#ifndef DEVICE_ASSIGNMENT_HPP_
#define DEVICE_ASSIGNMENT_HPP_

#include "openthread-core-config.h"

#include <stdint.h>
#include <string.h>

#if OPENTHREAD_FTD
#include "thread/child_table.hpp"
#endif

namespace ot {

static constexpr uint8_t kNetworkKeySize = 16;

struct PanIdAssignment
{
    uint16_t mPanId;
    uint8_t  mNetworkKey[kNetworkKeySize];
};

static const PanIdAssignment sPanIdPool[] = {
    {
        0x1234,
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    },
    {
        0x5678,
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
         0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
    },
};

static constexpr uint8_t kPanIdPoolSize = sizeof(sPanIdPool) / sizeof(sPanIdPool[0]);

inline const PanIdAssignment *FindPanIdAssignment(uint16_t aPanId)
{
    for (const auto &entry : sPanIdPool)
    {
        if (entry.mPanId == aPanId)
        {
            return &entry;
        }
    }

    return nullptr;
}

#if OPENTHREAD_FTD

// Round-robin allocator: returns the next PanIdAssignment whose PAN ID
// is not currently held by any child in aChildTable.  A static index
// ensures consecutive calls hand out different entries even when both
// callers run before either device appears in the child table.
inline const PanIdAssignment *AllocateNextPanId(ChildTable &aChildTable)
{
    static uint8_t sNextPoolIndex = 0;

    for (uint8_t i = 0; i < kPanIdPoolSize; i++)
    {
        uint8_t                index     = (sNextPoolIndex + i) % kPanIdPoolSize;
        const PanIdAssignment &candidate = sPanIdPool[index];
        bool                   inUse     = false;

        for (Child &child : aChildTable.Iterate(Child::kInStateValidOrRestoring))
        {
            if (child.GetPanId() == candidate.mPanId)
            {
                inUse = true;
                break;
            }
        }

        if (!inUse)
        {
            sNextPoolIndex = (index + 1) % kPanIdPoolSize;
            return &candidate;
        }
    }

    return nullptr;
}

#endif // OPENTHREAD_FTD

} // namespace ot

#endif // DEVICE_ASSIGNMENT_HPP_
