{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedRecordDot #-}

-- |
-- Module: Language.Bitcoin.Script.Descriptors.Utils
-- Stability: experimental
module Language.Bitcoin.Script.Descriptors.Utils (
    -- * Conversions
    descriptorAddresses,
    compile,
    compileTree,
    compileTapLeaf,

    -- * Transaction pieces
    TransactionScripts (..),
    outputDescriptorScripts,

    -- * Script families
    keyAtIndex,
    keyDescriptorAtIndex,
    scriptDescriptorAtIndex,
    treeDescriptorAtIndex,
    outputDescriptorAtIndex,

    -- * Pub keys
    outputDescriptorPubKeys,
    scriptDescriptorPubKeys,
    treeDescriptorPubKeys,

    -- * PSBT
    toPsbtInput,
    PsbtInputError (..),
) where

import Control.Applicative ((<|>))
import Control.Exception (Exception)
import Data.Functor ((<&>))
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HM
import Data.List (sortOn)
import Data.Maybe (fromMaybe, mapMaybe, maybeToList)
import Data.Serialize (decode)
import Data.Word (Word32)
import Haskoin.Address (
    Address (..),
    payToNestedScriptAddress,
    payToScriptAddress,
    payToWitnessScriptAddress,
    pubKeyAddr,
    pubKeyCompatWitnessAddr,
    pubKeyWitnessAddr,
 )
import Haskoin.Crypto (
    DerivPath,
    DerivPathI (..),
    Fingerprint,
    KeyIndex,
    PublicKey (..),
    addressHash,
    pathToList,
    xPubFP,
    (++/),
 )
import Haskoin.Script (
    Script (..),
    ScriptOp (..),
    ScriptOutput (..),
    encodeOutput,
    opPushData,
    sortMulSig,
    toP2SH,
    toP2WSH,
 )
import Haskoin.Transaction (
    Input (..),
    MAST (..),
    TaprootOutput (..),
    Tx (..),
    XOnlyPubKey (..),
    emptyInput,
    taprootOutputKey,
 )
import Haskoin.Util (eitherToMaybe, marshal)
import qualified Language.Bitcoin.Miniscript.Compiler as M (compile)
import qualified Language.Bitcoin.Miniscript.Syntax as M (key, keyH, multi)
import Language.Bitcoin.Script.Descriptors.Syntax (
    Key (..),
    KeyCollection (..),
    KeyDescriptor (KeyDescriptor, keyDef),
    OutputDescriptor (..),
    ScriptDescriptor (..),
    TreeDescriptor (..),
    derivation,
    fingerprint,
    keyBytes,
    keyDescPubKey,
 )
import Language.Bitcoin.Utils (globalContext)


-- | Get the set of addresses associated with an output descriptor.  The list will be empty if:
--
--      * any keys are indefinite
--      * the output is p2pk
--      * the output has a non-standard script
--
--      The list can contain more than one address in the case of the "combo" construct.
descriptorAddresses :: OutputDescriptor -> [Address]
descriptorAddresses = \case
    ScriptPubKey Pk{} -> mempty
    ScriptPubKey (Pkh key) -> maybeToList $ pubKeyAddr globalContext <$> keyDescPubKey key
    P2SH descriptor -> maybeToList $ payToScriptAddress globalContext <$> scriptDescriptorOutput descriptor
    P2WPKH key -> maybeToList $ pubKeyWitnessAddr globalContext <$> keyDescPubKey key
    P2WSH descriptor -> maybeToList $ payToWitnessScriptAddress globalContext <$> scriptDescriptorOutput descriptor
    WrappedWPkh key -> maybeToList $ pubKeyCompatWitnessAddr globalContext <$> keyDescPubKey key
    WrappedWSh descriptor -> maybeToList $ payToNestedScriptAddress globalContext <$> scriptDescriptorOutput descriptor
    Combo key
        | Just pk <- keyDescPubKey key ->
            [pubKeyAddr globalContext pk]
                <> if pk.compress
                    then
                        [ pubKeyWitnessAddr globalContext pk
                        , pubKeyCompatWitnessAddr globalContext pk
                        ]
                    else mempty
    P2TR key descriptor ->
        maybeToList $
            payToTaprootAddress <$> taprootDescriptorOutput key descriptor
    Addr addr -> [addr]
    _ -> mempty
  where
    payToTaprootAddress =
        p2trAddr
            . marshal globalContext
            . XOnlyPubKey
            . taprootOutputKey globalContext
    p2trAddr = WitnessAddress 0x01


scriptDescriptorOutput :: ScriptDescriptor -> Maybe ScriptOutput
scriptDescriptorOutput = \case
    Pk key -> PayPK <$> keyDescPubKey key
    Pkh key -> PayPKHash . addressHash . marshal globalContext <$> keyDescPubKey key
    Multi k ks -> PayMulSig <$> traverse keyDescPubKey ks <*> pure k
    SortedMulti k ks -> sortMulSig globalContext <$> (PayMulSig <$> traverse keyDescPubKey ks <*> pure k)
    _ -> Nothing


-- | Produce the taproot output described by the tree descriptor. Fails when any
--  keys in the descriptor are indeterminate or an illegal expression occurs in the
--  tree descriptor.
taprootDescriptorOutput ::
    KeyDescriptor -> Maybe TreeDescriptor -> Maybe TaprootOutput
taprootDescriptorOutput kd td = do
    pk <- keyDescPubKey kd
    mast <- maybe (Just Nothing) (fmap Just . compileTree) td
    return $ TaprootOutput pk.point mast


-- | Produce the script described by the descriptor.  Fails when any keys in the descriptor are indeterminate.
compile :: ScriptDescriptor -> Maybe Script
compile = \case
    Pk key -> compileMaybe $ M.key key
    Pkh key -> compileMaybe $ M.keyH key
    Multi k ks -> compileMaybe $ M.multi k ks
    SortedMulti k ks -> compileMaybe . M.multi k $ sortOn keyBytes ks
    Raw bs -> eitherToMaybe $ decode bs
  where
    compileMaybe = eitherToMaybe . M.compile


-- | Produce the MAST described by the tree descriptor. Fails when any keys in
--  the descriptor are indeterminate or an illegal expression occurs in the taproot
--  tree.
compileTree :: TreeDescriptor -> Maybe MAST
compileTree = \case
    TapLeaf script -> MASTLeaf 0xc0 <$> compileTapLeaf script
    TapBranch left right ->
        MASTBranch <$> compileTree left <*> compileTree right


-- | Produce the script described by the descriptor in a taproot leaf context.
--  Fails when any keys in the descriptor are indeterminate or the script
--  descriptor is illegal in a taproot descriptor leaf. Only `Pk` expressions are
--  currently permitted.
compileTapLeaf :: ScriptDescriptor -> Maybe Script
compileTapLeaf = \case
    Pk keyDesc -> do
        pubKey <- keyDescPubKey keyDesc
        return $
            Script
                [ opPushData . marshal globalContext $ XOnlyPubKey pubKey.point
                , OP_CHECKSIG
                ]
    Pkh{} -> Nothing
    Multi{} -> Nothing
    SortedMulti{} -> Nothing
    Raw{} -> Nothing


data TransactionScripts = TransactionScripts
    { txScriptPubKey :: Script
    , txRedeemScript :: Maybe Script
    , txWitnessScript :: Maybe Script
    }
    deriving (Eq, Show)


outputDescriptorScripts :: OutputDescriptor -> Maybe TransactionScripts
outputDescriptorScripts =
    \case
        ScriptPubKey sd ->
            compile sd <&> \theScriptPubKey ->
                TransactionScripts
                    { txScriptPubKey = theScriptPubKey
                    , txRedeemScript = Nothing
                    , txWitnessScript = Nothing
                    }
        P2SH sd ->
            compile sd <&> \theScript ->
                TransactionScripts
                    { txScriptPubKey = encodeOutput globalContext $ toP2SH theScript
                    , txRedeemScript = Just theScript
                    , txWitnessScript = Nothing
                    }
        P2WPKH kd -> do
            theScriptPubKey <-
                encodeOutput globalContext
                    . PayWitnessPKHash
                    . addressHash
                    . marshal globalContext
                    <$> keyDescPubKey kd
            pure
                TransactionScripts
                    { txScriptPubKey = theScriptPubKey
                    , txRedeemScript = Nothing
                    , txWitnessScript = Nothing
                    }
        P2WSH sd ->
            compile sd <&> \theScript ->
                TransactionScripts
                    { txScriptPubKey = encodeOutput globalContext $ toP2WSH theScript
                    , txRedeemScript = Nothing
                    , txWitnessScript = Just theScript
                    }
        WrappedWPkh kd -> do
            theRedeemScript <-
                encodeOutput globalContext
                    . PayWitnessPKHash
                    . addressHash
                    . marshal globalContext
                    <$> keyDescPubKey kd
            pure
                TransactionScripts
                    { txScriptPubKey = encodeOutput globalContext $ toP2SH theRedeemScript
                    , txRedeemScript = Just theRedeemScript
                    , txWitnessScript = Nothing
                    }
        WrappedWSh sd ->
            compile sd <&> \theScript ->
                let theRedeemScript = encodeOutput globalContext $ toP2WSH theScript
                 in TransactionScripts
                        { txScriptPubKey = encodeOutput globalContext $ toP2SH theRedeemScript
                        , txRedeemScript = Just theRedeemScript
                        , txWitnessScript = Just theScript
                        }
        Combo _kd -> Nothing
        P2TR{} -> Nothing
        Addr _ad -> Nothing


-- | For key families, get the key at the given index.  Otherwise, return the input key.
--
--   @since 0.2.1
keyAtIndex :: Word32 -> Key -> Key
keyAtIndex ix = \case
    XPub xpub path HardKeys -> XPub xpub (path :| ix) Single
    XPub xpub path SoftKeys -> XPub xpub (path :/ ix) Single
    key -> key


-- | Specialize key families occurring in the descriptor to the given index
--
--  @since 0.2.1
outputDescriptorAtIndex :: KeyIndex -> OutputDescriptor -> OutputDescriptor
outputDescriptorAtIndex ix = \case
    o@ScriptPubKey{} -> o
    P2SH sd -> P2SH $ scriptDescriptorAtIndex ix sd
    P2WPKH kd -> P2WPKH $ keyDescriptorAtIndex ix kd
    P2WSH sd -> P2WSH $ scriptDescriptorAtIndex ix sd
    WrappedWPkh kd -> WrappedWPkh $ keyDescriptorAtIndex ix kd
    WrappedWSh sd -> WrappedWSh $ scriptDescriptorAtIndex ix sd
    Combo kd -> Combo $ keyDescriptorAtIndex ix kd
    P2TR kd td ->
        P2TR (keyDescriptorAtIndex ix kd) (treeDescriptorAtIndex ix <$> td)
    a@Addr{} -> a


-- | Specialize key families occurring in the descriptor to the given index
--
--  @since 0.2.1
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
--
--  @since 0.2.1
keyDescriptorAtIndex :: KeyIndex -> KeyDescriptor -> KeyDescriptor
keyDescriptorAtIndex ix keyDescriptor = keyDescriptor{keyDef = keyAtIndex ix $ keyDef keyDescriptor}


-- | Specialize key families occurring in the tree descriptor to the given index
treeDescriptorAtIndex :: KeyIndex -> TreeDescriptor -> TreeDescriptor
treeDescriptorAtIndex ix = \case
    TapLeaf sd -> TapLeaf $ scriptDescriptorAtIndex ix sd
    TapBranch l r ->
        TapBranch (treeDescriptorAtIndex ix l) (treeDescriptorAtIndex ix r)


-- | Produce the psbt input parameters needed to spend an output from the
-- descriptor.  Caveat: This construction fails on `Combo` and `Addr` outputs.
--
--  @since 0.2.1
toPsbtInput ::
    -- | Transaction being spent
    Tx ->
    -- | Output being spent
    Int ->
    -- | Descriptor for output being spent
    OutputDescriptor ->
    Either PsbtInputError Input
toPsbtInput tx ix descriptor = case descriptor of
    ScriptPubKey sd ->
        pure
            emptyInput
                { nonWitnessUtxo = Just tx
                , inputHDKeypaths = hdPaths sd
                }
    P2SH sd -> do
        script <- compileForInput sd
        pure
            emptyInput
                { nonWitnessUtxo = Just tx
                , inputRedeemScript = Just script
                , inputHDKeypaths = hdPaths sd
                }
    P2WPKH kd -> do
        output <- tx.outputs `safeIndex` ix
        pure
            emptyInput
                { witnessUtxo = Just output
                , inputHDKeypaths = hdPath kd
                }
    P2WSH sd -> do
        output <- tx.outputs `safeIndex` ix
        script <- compileForInput sd
        pure
            emptyInput
                { witnessUtxo = Just output
                , inputWitnessScript = Just script
                , inputHDKeypaths = hdPaths sd
                }
    WrappedWPkh kd -> do
        output <- tx.outputs `safeIndex` ix
        k <- maybe (Left $ KeyNotAvailable kd) pure $ keyDescPubKey kd
        pure
            emptyInput
                { witnessUtxo = Just output
                , inputRedeemScript =
                    Just
                        . encodeOutput globalContext
                        . PayWitnessPKHash
                        . addressHash
                        $ marshal globalContext k
                , inputHDKeypaths = hdPath kd
                }
    WrappedWSh sd -> do
        output <- tx.outputs `safeIndex` ix
        script <- compileForInput sd
        pure
            emptyInput
                { witnessUtxo = Just output
                , inputRedeemScript = Just . encodeOutput globalContext $ toP2WSH script
                , inputWitnessScript = Just script
                , inputHDKeypaths = hdPaths sd
                }
    P2TR kd td -> do
        output <- tx.outputs `safeIndex` ix
        pure
            emptyInput
                { witnessUtxo = Just output
                , inputHDKeypaths =
                    hdPath kd
                        <> maybe mempty treeHdPaths td
                }
    o@Combo{} -> Left $ InvalidOutput o
    o@Addr{} -> Left $ InvalidOutput o
  where
    hdPaths = foldMap hdPath . scriptKeys
    treeHdPaths = foldMap hdPaths . treeScripts
    compileForInput sd = maybe (Left $ CompileError sd) pure $ compile sd

    safeIndex (x : xs) n
        | n == 0 = pure x
        | n > 0 = safeIndex xs (n - 1)
    safeIndex _ _ = Left $ OutputIndexOOB tx ix


data PsbtInputError
    = OutputIndexOOB Tx Int
    | CompileError ScriptDescriptor
    | KeyNotAvailable KeyDescriptor
    | InvalidOutput OutputDescriptor
    deriving (Eq, Show)


instance Exception PsbtInputError


hdPath :: KeyDescriptor -> HashMap PublicKey (Fingerprint, [KeyIndex])
hdPath k@(KeyDescriptor origin theKeyDef) = fromMaybe mempty $ do
    pubKey <- keyDescPubKey k
    fromOrigin pubKey <|> fromKey pubKey
  where
    fromOrigin pubKey = do
        theOrigin <- origin
        theKeyPath <- keyPath theKeyDef
        pure $
            HM.singleton
                pubKey
                ( fingerprint theOrigin
                , pathToList $ derivation theOrigin ++/ theKeyPath
                )
    fromKey pubKey =
        case theKeyDef of
            XPub xpub path Single ->
                pure $
                    HM.singleton
                        pubKey
                        ( xPubFP globalContext xpub
                        , pathToList path
                        )
            _ -> Nothing


keyPath :: Key -> Maybe DerivPath
keyPath = \case
    XPub _ path Single -> Just path
    _ -> Nothing


scriptKeys :: ScriptDescriptor -> [KeyDescriptor]
scriptKeys = \case
    Pk k -> [k]
    Pkh k -> [k]
    Multi _ ks -> ks
    SortedMulti _ ks -> ks
    Raw{} -> mempty


treeScripts :: TreeDescriptor -> [ScriptDescriptor]
treeScripts = \case
    TapLeaf sd -> [sd]
    TapBranch l r -> treeScripts l <> treeScripts r


-- | Extract pubkeys from an 'OutputDescriptor' where possible
outputDescriptorPubKeys :: OutputDescriptor -> [PublicKey]
outputDescriptorPubKeys = \case
    ScriptPubKey sd -> scriptDescriptorPubKeys sd
    P2SH sd -> scriptDescriptorPubKeys sd
    P2WPKH kd -> foldMap pure $ keyDescPubKey kd
    P2WSH sd -> scriptDescriptorPubKeys sd
    WrappedWPkh kd -> foldMap pure $ keyDescPubKey kd
    WrappedWSh sd -> scriptDescriptorPubKeys sd
    Combo kd -> foldMap pure $ keyDescPubKey kd
    P2TR kd td ->
        foldMap pure (keyDescPubKey kd)
            <> concatMap treeDescriptorPubKeys td
    Addr _ad -> mempty


-- | Extract pubkeys from a 'ScriptDescriptor' where possible
scriptDescriptorPubKeys :: ScriptDescriptor -> [PublicKey]
scriptDescriptorPubKeys = mapMaybe keyDescPubKey . scriptKeys


-- | Extract pubkeys from a 'TreeDescriptor' where possible
treeDescriptorPubKeys :: TreeDescriptor -> [PublicKey]
treeDescriptorPubKeys = \case
    TapLeaf sd -> scriptDescriptorPubKeys sd
    TapBranch left right ->
        treeDescriptorPubKeys left <> treeDescriptorPubKeys right
