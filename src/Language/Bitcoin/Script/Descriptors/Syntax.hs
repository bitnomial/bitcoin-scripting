module Language.Bitcoin.Script.Descriptors.Syntax (
    ScriptDescriptor (..),
    KeyDescriptor (..),
    Origin (..),
    Key (..),
    KeyCollection (..),
    pubKey,
    secKey,
    keyDescPubKey,
    keyBytes,
) where

import Data.ByteString (ByteString)
import Haskoin.Address (Address)
import Haskoin.Keys (
    DerivPath,
    Fingerprint,
    PubKeyI (..),
    SecKeyI,
    XPubKey,
    derivePubKeyI,
    exportPubKey,
 )

data ScriptDescriptor
    = -- | P2SH embed the argument.
      Sh ScriptDescriptor
    | -- | P2WSH embed the argument.
      Wsh ScriptDescriptor
    | -- | P2PK output for the given public key.
      Pk KeyDescriptor
    | -- | P2PKH output for the given public key (use 'Addr' if you only know the pubkey hash).
      Pkh KeyDescriptor
    | -- | P2WPKH output for the given compressed pubkey.
      Wpkh KeyDescriptor
    | -- | An alias for the collection of pk(KEY) and pkh(KEY). If the key is
      -- compressed, it also includes wpkh(KEY) and sh(wpkh(KEY)).
      Combo KeyDescriptor
    | -- | k-of-n multisig script.
      Multi Int [KeyDescriptor]
    | -- | k-of-n multisig script with keys sorted lexicographically in the resulting script.
      SortedMulti Int [KeyDescriptor]
    | -- | the script which ADDR expands to.
      Addr Address
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
      Pubkey PubKeyI
    | -- | (de)serialized as WIF
      SecretKey SecKeyI
    | XPub XPubKey DerivPath KeyCollection
    deriving (Eq, Show)

-- | Simple explicit public key with no origin information
pubKey :: PubKeyI -> KeyDescriptor
pubKey = KeyDescriptor Nothing . Pubkey

-- | Simple explicit secret key with no origin information
secKey :: SecKeyI -> KeyDescriptor
secKey = KeyDescriptor Nothing . SecretKey

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
    toBytes (PubKeyI pk c) = exportPubKey c pk

-- | Produce a pubkey if possible
keyDescPubKey :: KeyDescriptor -> Maybe PubKeyI
keyDescPubKey (KeyDescriptor _ k) = case k of
    Pubkey pk -> Just pk
    SecretKey sk -> Just $ derivePubKeyI sk
    _ -> Nothing
