#ifndef PAN_ID_ASSIGNMENT_HPP_
#define PAN_ID_ASSIGNMENT_HPP_

#include <stdint.h>

namespace ot {

static constexpr uint8_t kNetworkKeySize = 16;

struct PanIdAssignment
{
    uint16_t mPanId;
    uint8_t  mNetworkKey[kNetworkKeySize];
};

} // namespace ot

#endif // PAN_ID_ASSIGNMENT_HPP_
