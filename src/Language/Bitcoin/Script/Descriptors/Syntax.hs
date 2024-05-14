{-# LANGUAGE OverloadedRecordDot #-}

module Language.Bitcoin.Script.Descriptors.Syntax (
    OutputDescriptor (..),
    ScriptDescriptor (..),
    KeyDescriptor (..),
    TreeDescriptor (..),
    isDefinite,
    keyDescPubKey,
    keyBytes,
    Origin (..),
    Key (..),
    KeyCollection (..),
    pubKey,
    secKey,
    xOnlyPubKey,
) where

import Data.ByteString (ByteString)
import Haskoin.Address (Address)
import Haskoin.Crypto (
    DerivPath,
    Fingerprint,
    PrivateKey,
    PublicKey (..),
    XPubKey (..),
    derivePubPath,
    derivePublicKey,
    exportPubKey,
    toSoft,
    wrapPubKey,
 )
import Haskoin.Transaction (XOnlyPubKey (..))
import Language.Bitcoin.Utils (globalContext)


-- | High level description for a bitcoin output
data OutputDescriptor
    = -- | The output is secured by the given script.
      ScriptPubKey ScriptDescriptor
    | -- | P2SH embed the argument.
      P2SH ScriptDescriptor
    | -- | P2WPKH output for the given compressed pubkey.
      P2WPKH KeyDescriptor
    | -- | P2WSH embed the argument.
      P2WSH ScriptDescriptor
    | -- | P2SH-P2WPKH the given compressed pubkey.
      WrappedWPkh KeyDescriptor
    | -- | P2SH-P2WSH the given script
      WrappedWSh ScriptDescriptor
    | -- | An alias for the collection of pk(KEY) and pkh(KEY). If the key is
      -- compressed, it also includes wpkh(KEY) and sh(wpkh(KEY)).
      Combo KeyDescriptor
    | -- | A P2TR output with the specified key and an optional tree of script
      -- paths
      P2TR KeyDescriptor (Maybe TreeDescriptor)
    | -- | The script which ADDR expands to.
      Addr Address
    deriving (Eq, Show)


-- | High level description of a bitcoin script
data ScriptDescriptor
    = -- | Require a signature for this key
      Pk KeyDescriptor
    | -- | Require a key matching this hash and a signature for that key
      Pkh KeyDescriptor
    | -- | k-of-n multisig script.
      Multi Int [KeyDescriptor]
    | -- | k-of-n multisig script with keys sorted lexicographically in the resulting script.
      SortedMulti Int [KeyDescriptor]
    | -- | the script whose hex encoding is HEX.
      Raw ByteString
    deriving (Eq, Show)


data KeyDescriptor = KeyDescriptor
    { origin :: Maybe Origin
    , keyDef :: Key
    }
    deriving (Eq, Show)


data Origin = Origin
    { fingerprint :: Fingerprint
    , derivation :: DerivPath
    }
    deriving (Eq, Ord, Show)


data Key
    = -- | DER-hex encoded secp256k1 public key
      PubKey PublicKey
    | -- | (de)serialized as WIF
      SecretKey PrivateKey
    | XPub XPubKey DerivPath KeyCollection
    | -- | An x-only public key. The representation type used will change in the
      -- future.
      XOnlyPub XOnlyPubKey
    deriving (Eq, Show)


data TreeDescriptor
    = TapLeaf ScriptDescriptor
    | TapBranch TreeDescriptor TreeDescriptor
    deriving (Eq, Show)


-- | Simple explicit public key with no origin information
pubKey :: PublicKey -> KeyDescriptor
pubKey = KeyDescriptor Nothing . PubKey


-- | Simple explicit secret key with no origin information
secKey :: PrivateKey -> KeyDescriptor
secKey = KeyDescriptor Nothing . SecretKey


-- | Simple explicit x-only public key with no origin information
xOnlyPubKey :: XOnlyPubKey -> KeyDescriptor
xOnlyPubKey = KeyDescriptor Nothing . XOnlyPub


-- | Represent whether the key corresponds to a collection (and how) or a single key.
data KeyCollection
    = Single
    | -- | immediate hardened children
      HardKeys
    | -- | immediate non-hardened children
      SoftKeys
    deriving (Eq, Ord, Show)


-- | Produce a key literal if possible
keyBytes :: KeyDescriptor -> Maybe ByteString
keyBytes = fmap toBytes . keyDescPubKey
  where
    toBytes (PublicKey pk c) = exportPubKey globalContext c pk


-- | Produce a pubkey if possible
keyDescPubKey :: KeyDescriptor -> Maybe PublicKey
keyDescPubKey (KeyDescriptor _ k) = case k of
    PubKey pk -> Just pk
    SecretKey sk -> Just $ derivePublicKey globalContext sk
    XPub xpub path Single -> do
        sp <- toSoft path
        pure $ PublicKey (derivePubPath globalContext sp xpub).key True
    XOnlyPub (XOnlyPubKey pk) -> Just $ wrapPubKey True pk
    _ -> Nothing


-- | Test whether the key descriptor corresponds to a single key
isDefinite :: KeyDescriptor -> Bool
isDefinite (KeyDescriptor _ k) = case k of
    XPub _ _ HardKeys -> False
    XPub _ _ SoftKeys -> False
    _ -> True
