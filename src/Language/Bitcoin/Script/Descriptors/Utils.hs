{-# LANGUAGE LambdaCase #-}

module Language.Bitcoin.Script.Descriptors.Utils (
    descriptorAddresses,
    compile,
) where

import Data.List (sortOn)
import Data.Maybe (maybeToList)
import Data.Serialize (decode, encode)
import Haskoin (
    Address,
    Script,
    ScriptOutput (..),
    addressHash,
    eitherToMaybe,
    payToNestedScriptAddress,
    payToScriptAddress,
    payToWitnessScriptAddress,
    pubKeyAddr,
    pubKeyCompatWitnessAddr,
    pubKeyCompressed,
    pubKeyWitnessAddr,
    sortMulSig,
 )

import qualified Language.Bitcoin.Miniscript as M
import Language.Bitcoin.Script.Descriptors.Syntax (
    OutputDescriptor (..),
    ScriptDescriptor (..),
    keyBytes,
    keyDescPubKey,
 )

{- | Get the set of addresses associated with an output descriptor.  The list will be empty if:

     * any keys are indefinite
     * the output is p2pk
     * the output has a non-standard script

     The list can contain more than one address in the case of the "combo" construct.
-}
descriptorAddresses :: OutputDescriptor -> [Address]
descriptorAddresses = \case
    ScriptPubKey Pk{} -> mempty
    ScriptPubKey (Pkh key) -> foldMap (pure . pubKeyAddr) $ keyDescPubKey key
    P2SH descriptor -> maybeToList $ payToScriptAddress <$> scriptDescriptorOutput descriptor
    P2WPKH key -> foldMap (pure . pubKeyWitnessAddr) $ keyDescPubKey key
    P2WSH descriptor -> maybeToList $ payToWitnessScriptAddress <$> scriptDescriptorOutput descriptor
    WrappedWPkh key -> foldMap (pure . pubKeyCompatWitnessAddr) $ keyDescPubKey key
    WrappedWSh descriptor -> maybeToList $ payToNestedScriptAddress <$> scriptDescriptorOutput descriptor
    Combo key
        | Just pk <- keyDescPubKey key ->
            [pubKeyAddr pk]
                <> if pubKeyCompressed pk
                    then [pubKeyWitnessAddr pk, pubKeyCompatWitnessAddr pk]
                    else mempty
    Addr addr -> [addr]
    _ -> mempty

scriptDescriptorOutput :: ScriptDescriptor -> Maybe ScriptOutput
scriptDescriptorOutput = \case
    Pk key -> PayPK <$> keyDescPubKey key
    Pkh key -> PayPKHash . addressHash . encode <$> keyDescPubKey key
    Multi k ks -> PayMulSig <$> traverse keyDescPubKey ks <*> pure k
    SortedMulti k ks -> sortMulSig <$> (PayMulSig <$> traverse keyDescPubKey ks <*> pure k)
    _ -> Nothing

-- | Produce the script described by the descriptor.  Fails when any keys in the descriptor are indeterminate.
compile :: ScriptDescriptor -> Maybe Script
compile = \case
    Pk key -> compileMaybe $ M.key key
    Pkh key -> compileMaybe $ M.keyH key
    Multi k ks -> compileMaybe $ M.multi k ks
    SortedMulti k ks -> compileMaybe $ M.multi k (sortOn keyBytes ks)
    Raw bs -> eitherToMaybe (decode bs)
  where
    compileMaybe = eitherToMaybe . M.compile
