{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NumericUnderscores #-}

module Language.Bitcoin.Script.Descriptors.Utils (
    -- * Conversions
    descriptorAddresses,
    compile,

    -- * Transaction size
    estimateTxSize,
    txWeight,

    -- * Script families
    keyAtIndex,
    keyDescriptorAtIndex,
    scriptDescriptorAtIndex,
    outputDescriptorAtIndex,
) where

import Control.Monad (replicateM, zipWithM)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (Except, runExcept, throwE)
import Control.Monad.Trans.State.Strict (StateT, get, put, runStateT)
import Data.Bifunctor (second)
import qualified Data.ByteString as BS
import Data.List (sortOn)
import Data.Maybe (mapMaybe, maybeToList)
import Data.Serialize (decode, encode)
import Data.Word (Word32)
import Haskoin (
    Address,
    DerivPathI ((:/), (:|)),
    Hash160,
    KeyIndex,
    PubKeyI (..),
    Script,
    ScriptOutput (..),
    SecKey,
    SigInput (SigInput),
    Tx,
    TxIn,
    addressHash,
    btc,
    derivePubKey,
    eitherToMaybe,
    encodeOutput,
    payToNestedScriptAddress,
    payToScriptAddress,
    payToWitnessScriptAddress,
    prevOutput,
    pubKeyAddr,
    pubKeyCompatWitnessAddr,
    pubKeyCompressed,
    pubKeyWitnessAddr,
    secKey,
    sigHashAll,
    sortMulSig,
    toP2SH,
    toP2WSH,
    txIn,
    txWitness,
 )
import Haskoin.Transaction.Builder.Sign (signTx)

import qualified Language.Bitcoin.Miniscript as M
import Language.Bitcoin.Script.Descriptors.Syntax (
    Key (XPub),
    KeyCollection (..),
    KeyDescriptor (keyDef),
    OutputDescriptor (..),
    ScriptDescriptor (..),
    keyBytes,
    keyDescPubKey,
 )

{- | Estimate the final size of the signed transaction by creating a mock signed transaction with the
 same output types, when possible.  We assume that the list of 'OutputDescriptor' values is the
 list of inputs and ignore the 'txIn' field of the input 'Tx'.  This function
 fails on 'ScriptPubKey', 'Combo', and 'Addr' inputs.
-}
estimateTxSize :: [OutputDescriptor] -> Tx -> Either String Int
-- TODO Calculate tx size bounds directly
estimateTxSize inputs tx = do
    (sigInputs, ks) <- runExcept . runMockState mockSecKeys $ zipWithM mockSigInput (txIn tx) inputs
    txWeight <$> signTx btc tx sigInputs ks

{- | Calculate the weight of a transaction.  See
 <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-size-calculations>
-}
txWeight :: Tx -> Int
txWeight tx =
    3 * baseWeight + totalWeight
  where
    totalWeight = (BS.length . encode) tx
    baseWeight = (BS.length . encode) baseTx
    baseTx = tx{txWitness = mempty}

-- | In order to reduce estimation bias we use as many keys as possible, tracking them in this structure
data MockState = MockState
    { usedKeys :: [SecKey]
    , unusedKeys :: [SecKey]
    }
    deriving (Eq, Show)

runMockState :: Functor m => [SecKey] -> StateT MockState m a -> m (a, [SecKey])
runMockState ks go = second usedKeys <$> runStateT go (MockState mempty ks)

-- | Get the next available unused key
useKey :: StateT MockState (Except String) SecKey
useKey =
    get >>= \case
        s@MockState{unusedKeys = k : ks, usedKeys = uks} -> do
            put s{usedKeys = k : uks, unusedKeys = ks}
            pure k
        _ -> lift $ throwE "Key list exhausted"

usePubKey :: StateT MockState (Except String) PubKeyI
usePubKey = (`PubKeyI` True) . derivePubKey <$> useKey

-- | Create signing data for a mock version of the given output descriptor
mockSigInput ::
    TxIn ->
    OutputDescriptor ->
    StateT MockState (Except String) (SigInput, Bool)
mockSigInput theTxIn = \case
    ScriptPubKey{} -> lift $ throwE "ScriptPubKey"
    P2SH script -> do
        rs <- redeemScript script
        mkSigInput (toP2SH $ encodeOutput rs) (Just rs) False
    P2WPKH{} -> do
        h <- keyHash <$> usePubKey
        mkSigInput (PayWitnessPKHash h) Nothing False
    P2WSH script -> do
        rs <- redeemScript script
        mkSigInput (toP2WSH $ encodeOutput rs) (Just rs) False
    WrappedWPkh{} -> do
        h <- keyHash <$> usePubKey
        mkSigInput (PayWitnessPKHash h) Nothing True
    WrappedWSh script -> do
        rs <- redeemScript script
        mkSigInput (toP2WSH $ encodeOutput rs) (Just rs) True
    Combo{} -> lift $ throwE "Combo"
    Addr{} -> lift $ throwE "Addr"
  where
    mkSigInput theScript theRedeemScript isNestedWitness =
        pure
            ( SigInput theScript 1_0000_0000 (prevOutput theTxIn) sigHashAll theRedeemScript
            , isNestedWitness
            )

-- Hash used for P2PKH, P2WPKH etc.
keyHash :: PubKeyI -> Hash160
keyHash = addressHash . encode

-- | For script-hash spends, calculate the redeem script
redeemScript :: ScriptDescriptor -> StateT MockState (Except String) ScriptOutput
redeemScript = \case
    Pk{} -> PayPK <$> usePubKey
    Pkh{} -> PayPKHash . keyHash <$> usePubKey
    Multi k ks -> PayMulSig <$> getPubKeys (length ks) <*> pure k
    SortedMulti k ks -> PayMulSig <$> getPubKeys (length ks) <*> pure k
    Raw{} -> lift $ throwE "Raw"
  where
    getPubKeys n = replicateM n usePubKey

-- | A large collection of mock secret keys
mockSecKeys :: [SecKey]
mockSecKeys = mapMaybe (secKey . uncurry mkRawKey) [(i, j) | i <- [0 .. 255], j <- [0 .. 255]]
  where
    mkRawKey i j = BS.pack $ i : j : replicate 30 0x1

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

-- | For key families, get the key at the given index.  Otherwise, return the input key.
keyAtIndex :: Word32 -> Key -> Key
keyAtIndex ix = \case
    XPub xpub path HardKeys -> XPub xpub (path :| ix) Single
    XPub xpub path SoftKeys -> XPub xpub (path :/ ix) Single
    key -> key

-- | Specialize key families occurring in the descriptor to the given index
outputDescriptorAtIndex :: KeyIndex -> OutputDescriptor -> OutputDescriptor
outputDescriptorAtIndex ix = \case
    o@ScriptPubKey{} -> o
    P2SH sd -> P2SH $ scriptDescriptorAtIndex ix sd
    P2WPKH kd -> P2WPKH $ keyDescriptorAtIndex ix kd
    P2WSH sd -> P2WSH $ scriptDescriptorAtIndex ix sd
    WrappedWPkh kd -> WrappedWPkh $ keyDescriptorAtIndex ix kd
    WrappedWSh sd -> WrappedWSh $ scriptDescriptorAtIndex ix sd
    Combo kd -> Combo $ keyDescriptorAtIndex ix kd
    a@Addr{} -> a

-- | Specialize key families occurring in the descriptor to the given index
scriptDescriptorAtIndex :: KeyIndex -> ScriptDescriptor -> ScriptDescriptor
scriptDescriptorAtIndex ix = \case
    Pk kd -> Pk $ specialize kd
    Pkh kd -> Pkh $ specialize kd
    Multi k ks -> Multi k $ specialize <$> ks
    SortedMulti k ks -> SortedMulti k $ specialize <$> ks
    r@Raw{} -> r
  where
    specialize = keyDescriptorAtIndex ix

-- | Specialize key families occurring in the descriptor to the given index
keyDescriptorAtIndex :: KeyIndex -> KeyDescriptor -> KeyDescriptor
keyDescriptorAtIndex ix keyDescriptor = keyDescriptor{keyDef = keyAtIndex ix $ keyDef keyDescriptor}
