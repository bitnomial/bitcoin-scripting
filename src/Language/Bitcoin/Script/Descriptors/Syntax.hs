{-# LANGUAGE LambdaCase #-}

module Language.Bitcoin.Script.Descriptors.Syntax (
    OutputDescriptor (..),
    ScriptDescriptor (..),
    KeyDescriptor (..),
    isDefinite,
    keyDescPubKey,
    keyBytes,
    Origin (..),
    Key (..),
    KeyCollection (..),
    pubKey,
    secKey,
) where

import Data.ByteString (ByteString)
import Haskoin (
    Address,
    DerivPath,
    Fingerprint,
    PubKeyI (..),
    SecKeyI,
    XPubKey (xPubKey),
    derivePubKeyI,
    derivePubPath,
    exportPubKey,
    toSoft,
 )

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
    XPub xpub path Single -> (`PubKeyI` True) . xPubKey . (`derivePubPath` xpub) <$> toSoft path
    _ -> Nothing

-- | Test whether the key descriptor corresponds to a single key
isDefinite :: KeyDescriptor -> Bool
isDefinite (KeyDescriptor _ k) = case k of
    XPub _ _ HardKeys -> False
    XPub _ _ SoftKeys -> False
    _ -> True
