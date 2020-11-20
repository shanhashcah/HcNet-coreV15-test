#pragma once
#include <xdr/Hcnet-types.h>

namespace std
{
template <> struct hash<hcnet::uint256>
{
    size_t operator()(hcnet::uint256 const& x) const noexcept;
};
}
