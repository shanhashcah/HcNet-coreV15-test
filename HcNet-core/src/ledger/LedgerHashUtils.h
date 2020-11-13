#pragma once

// Copyright 2018 HcNet Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/ShortHash.h"
#include "ledger/InternalLedgerEntry.h"
#include "xdr/HcNet-ledger.h"
#include <functional>

// implements a default hasher for "LedgerKey"
namespace std
{
template <> class hash<HcNet::Asset>
{
  public:
    size_t
    operator()(HcNet::Asset const& asset) const
    {
        size_t res = asset.type();
        switch (asset.type())
        {
        case HcNet::ASSET_TYPE_NATIVE:
            break;
        case HcNet::ASSET_TYPE_CREDIT_ALPHANUM4:
        {
            auto& a4 = asset.alphaNum4();
            res ^= HcNet::shortHash::computeHash(
                HcNet::ByteSlice(a4.issuer.ed25519().data(), 8));
            res ^= a4.assetCode[0];
            break;
        }
        case HcNet::ASSET_TYPE_CREDIT_ALPHANUM12:
        {
            auto& a12 = asset.alphaNum12();
            res ^= HcNet::shortHash::computeHash(
                HcNet::ByteSlice(a12.issuer.ed25519().data(), 8));
            res ^= a12.assetCode[0];
            break;
        }
        }
        return res;
    }
};

template <> class hash<HcNet::LedgerKey>
{
  public:
    size_t
    operator()(HcNet::LedgerKey const& lk) const
    {
        size_t res;
        switch (lk.type())
        {
        case HcNet::ACCOUNT:
            res = HcNet::shortHash::computeHash(
                HcNet::ByteSlice(lk.account().accountID.ed25519().data(), 8));
            break;
        case HcNet::TRUSTLINE:
        {
            auto& tl = lk.trustLine();
            res = HcNet::shortHash::computeHash(
                HcNet::ByteSlice(tl.accountID.ed25519().data(), 8));
            res ^= hash<HcNet::Asset>()(tl.asset);
            break;
        }
        case HcNet::DATA:
            res = HcNet::shortHash::computeHash(
                HcNet::ByteSlice(lk.data().accountID.ed25519().data(), 8));
            res ^= HcNet::shortHash::computeHash(HcNet::ByteSlice(
                lk.data().dataName.data(), lk.data().dataName.size()));
            break;
        case HcNet::OFFER:
            res = HcNet::shortHash::computeHash(HcNet::ByteSlice(
                &lk.offer().offerID, sizeof(lk.offer().offerID)));
            break;
        case HcNet::CLAIMABLE_BALANCE:
            res = HcNet::shortHash::computeHash(HcNet::ByteSlice(
                lk.claimableBalance().balanceID.v0().data(), 8));
            break;
        default:
            abort();
        }
        return res;
    }
};

template <> class hash<HcNet::InternalLedgerKey>
{
  public:
    size_t
    operator()(HcNet::InternalLedgerKey const& glk) const
    {
        switch (glk.type())
        {
        case HcNet::InternalLedgerEntryType::LEDGER_ENTRY:
            return hash<HcNet::LedgerKey>()(glk.ledgerKey());
        case HcNet::InternalLedgerEntryType::SPONSORSHIP:
            return HcNet::shortHash::computeHash(HcNet::ByteSlice(
                glk.sponsorshipKey().sponsoredID.ed25519().data(), 8));
        case HcNet::InternalLedgerEntryType::SPONSORSHIP_COUNTER:
            return HcNet::shortHash::computeHash(HcNet::ByteSlice(
                glk.sponsorshipCounterKey().sponsoringID.ed25519().data(), 8));
        default:
            abort();
        }
    }
};
}
