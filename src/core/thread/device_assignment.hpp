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

inline const PanIdAssignment *FindPanIdAssignment(const PanIdAssignment *aPool, uint8_t aPoolSize, uint16_t aPanId)
{
    for (uint8_t i = 0; i < aPoolSize; i++)
    {
        if (aPool[i].mPanId == aPanId)
        {
            return &aPool[i];
        }
    }

    return nullptr;
}

#if OPENTHREAD_FTD

inline const PanIdAssignment *AllocateNextPanId(const PanIdAssignment *aPool,
                                                uint8_t                aPoolSize,
                                                ChildTable            &aChildTable)
{
    static uint8_t sNextPoolIndex = 0;

    for (uint8_t i = 0; i < aPoolSize; i++)
    {
        uint8_t                index     = (sNextPoolIndex + i) % aPoolSize;
        const PanIdAssignment &candidate = aPool[index];
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
            sNextPoolIndex = (index + 1) % aPoolSize;
            return &candidate;
        }
    }

    return nullptr;
}

#endif // OPENTHREAD_FTD

} // namespace ot

#endif // DEVICE_ASSIGNMENT_HPP_
