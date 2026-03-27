#ifndef DEVICE_ASSIGNMENT_HPP_
#define DEVICE_ASSIGNMENT_HPP_

#include <stdint.h>
#include <string.h>

#include "mac/mac_types.hpp"
#include "meshcop/meshcop.hpp"

namespace ot {

static constexpr uint8_t kExtAddressSize  = 8;
static constexpr uint8_t kNetworkKeySize  = 16;

struct DeviceAssignment
{
    uint8_t  mEui64[kExtAddressSize];
    uint16_t mPanId;
    uint8_t  mNetworkKey[kNetworkKeySize];
};

static const DeviceAssignment sDeviceTable[] = {
    // ESP1: eui64 1051dbfffe008a0c, PAN 0x1234
    {
        {0x10, 0x51, 0xdb, 0xff, 0xfe, 0x00, 0x8a, 0x0c},
        0x1234,
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    },
    // ESP2: eui64 f0f5bdfffe025f58, PAN 0x5678
    {
        {0xf0, 0xf5, 0xbd, 0xff, 0xfe, 0x02, 0x5f, 0x58},
        0x5678,
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
         0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
    },
};

inline const DeviceAssignment *FindDeviceAssignment(const Mac::ExtAddress &aExtAddress)
{
    for (const auto &entry : sDeviceTable)
    {
        if (memcmp(aExtAddress.m8, entry.mEui64, kExtAddressSize) == 0)
        {
            return &entry;
        }
    }

    return nullptr;
}

inline const DeviceAssignment *FindDeviceAssignmentByJoinerId(const Mac::ExtAddress &aJoinerId)
{
    for (const auto &entry : sDeviceTable)
    {
        Mac::ExtAddress eui64;
        Mac::ExtAddress computedJoinerId;

        memcpy(eui64.m8, entry.mEui64, kExtAddressSize);
        MeshCoP::ComputeJoinerId(eui64, computedJoinerId);

        if (computedJoinerId == aJoinerId)
        {
            return &entry;
        }
    }

    return nullptr;
}

inline const DeviceAssignment *FindDeviceAssignmentByPanId(uint16_t aPanId)
{
    for (const auto &entry : sDeviceTable)
    {
        if (entry.mPanId == aPanId)
        {
            return &entry;
        }
    }

    return nullptr;
}

} // namespace ot

#endif // DEVICE_ASSIGNMENT_HPP_
