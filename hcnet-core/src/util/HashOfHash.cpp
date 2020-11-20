#include "HashOfHash.h"
#include "crypto/ShortHash.h"

namespace std
{

size_t
hash<hcnet::uint256>::operator()(hcnet::uint256 const& x) const noexcept
{
    size_t res =
        hcnet::shortHash::computeHash(hcnet::ByteSlice(x.data(), 8));

    return res;
}
}
