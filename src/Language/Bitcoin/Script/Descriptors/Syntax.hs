module Language.Bitcoin.Script.Descriptors.Syntax
    ( ScriptDescriptor (..)
    , KeyDescriptor (..)
    , Origin (..)
    , Key (..)
    , KeyCollection (..)
    , pubKey
    , secKey
    , keyDescPubKey
    , keyBytes
    ) where

import           Data.ByteString (ByteString)
import           Haskoin.Address (Address)
import           Haskoin.Keys    (DerivPath, Fingerprint, PubKeyI (..), SecKeyI,
                                  XPubKey, derivePubKeyI, exportPubKey)


data ScriptDescriptor
    = Sh ScriptDescriptor
    -- ^ P2SH embed the argument.
    | Wsh ScriptDescriptor
    -- ^ P2WSH embed the argument.
    | Pk KeyDescriptor
    -- ^ P2PK output for the given public key.
    | Pkh KeyDescriptor
    -- ^ P2PKH output for the given public key (use 'Addr' if you only know the pubkey hash).
    | Wpkh KeyDescriptor
    -- ^ P2WPKH output for the given compressed pubkey.
    | Combo KeyDescriptor
    -- ^ An alias for the collection of pk(KEY) and pkh(KEY). If the key is
    -- compressed, it also includes wpkh(KEY) and sh(wpkh(KEY)).
    | Multi Int [KeyDescriptor]
    -- ^ k-of-n multisig script.
    | SortedMulti Int [KeyDescriptor]
    -- ^ k-of-n multisig script with keys sorted lexicographically in the resulting script.
    | Addr Address
    -- ^ the script which ADDR expands to.
    | Raw ByteString
    -- ^ the script whose hex encoding is HEX.
    deriving (Eq, Show)


data KeyDescriptor = KeyDescriptor
    { origin :: Maybe Origin
    , keyDef :: Key
    } deriving (Eq, Show)


data Origin = Origin
    { fingerprint :: Fingerprint
    , derivation  :: DerivPath
    } deriving (Eq, Ord, Show)


data Key
    = Pubkey PubKeyI
    -- ^ DER-hex encoded secp256k1 public key
    | SecretKey SecKeyI
    -- ^ (de)serialized as WIF
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
    | HardKeys
    -- ^ immediate hardened children
    | SoftKeys
    -- ^ immediate non-hardened children
    deriving (Eq, Ord, Show)


-- | Produce a key literal if possible
keyBytes :: KeyDescriptor -> Maybe ByteString
keyBytes = fmap toBytes . keyDescPubKey
    where
    toBytes (PubKeyI pk c) = exportPubKey c pk


-- | Produce a pubkey if possible
keyDescPubKey :: KeyDescriptor -> Maybe PubKeyI
keyDescPubKey (KeyDescriptor _ k) = case k of
    Pubkey pk    -> Just pk
    SecretKey sk -> Just $ derivePubKeyI sk
    _            -> Nothing
