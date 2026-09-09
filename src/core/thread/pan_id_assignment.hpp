#ifndef PAN_ID_ASSIGNMENT_HPP_
#define PAN_ID_ASSIGNMENT_HPP_

#include <stdint.h>

namespace ot {

static constexpr uint8_t kNetworkKeySize = 16;

// Reserved Group ID meaning "unbound / available for round-robin" - i.e. a pool entry
// that no Commissioner Group Registry mapping currently claims. Group IDs handed to the
// Commissioner's group commands must be non-zero.
static constexpr uint8_t kUnboundGroupId = 0;

struct PanIdAssignment
{
    uint16_t mPanId;
    uint8_t  mNetworkKey[kNetworkKeySize];
    uint8_t  mGroupId; // kUnboundGroupId unless bound to a Commissioner group (see device_assignment.hpp)
};

} // namespace ot

#endif // PAN_ID_ASSIGNMENT_HPP_
