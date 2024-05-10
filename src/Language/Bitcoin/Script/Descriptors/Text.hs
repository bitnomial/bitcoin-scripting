{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Convert descriptors to text
module Language.Bitcoin.Script.Descriptors.Text (
    descriptorToText,
    descriptorToTextWithChecksum,
    keyDescriptorToText,
    treeDescriptorToText,
) where

import Data.Maybe (fromMaybe)
import Data.Text (
    Text,
    intercalate,
    pack,
 )
import Haskoin (
    Network,
    PubKeyI (..),
    addrToText,
    encodeHex,
    exportPubKey,
    fingerprintToText,
    pathToStr,
    toWif,
    xPubExport,
 )

import Data.Serialize (encode)
import qualified Data.Text as Text
import Language.Bitcoin.Script.Descriptors.Checksum (descriptorChecksum)
import Language.Bitcoin.Script.Descriptors.Syntax
import Language.Bitcoin.Utils (
    applicationText,
    showText,
 )


descriptorToText :: Network -> OutputDescriptor -> Text
descriptorToText net = \case
    ScriptPubKey x -> sdToText x
    P2SH x -> applicationText "sh" $ sdToText x
    P2WPKH k -> applicationText "wpkh" $ keyToText k
    P2WSH x -> applicationText "wsh" $ sdToText x
    WrappedWPkh k -> applicationText "sh" . applicationText "wpkh" $ keyToText k
    WrappedWSh x -> applicationText "sh" . applicationText "wsh" $ sdToText x
    Combo k -> applicationText "combo" $ keyToText k
    P2TR k tree ->
        applicationText "tr" $
            keyToText k <> maybe mempty (Text.cons ',' . treeToText) tree
    Addr a -> applicationText "addr" . fromMaybe addrErr $ addrToText net a
  where
    sdToText = scriptDescriptorToText net
    keyToText = keyDescriptorToText net
    treeToText = treeDescriptorToText net

    addrErr = error "Unable to parse address"


descriptorToTextWithChecksum :: Network -> OutputDescriptor -> Text
descriptorToTextWithChecksum net desc =
    descText <> maybe "" ("#" <>) (descriptorChecksum descText)
  where
    descText = descriptorToText net desc


scriptDescriptorToText :: Network -> ScriptDescriptor -> Text
scriptDescriptorToText net = \case
    Pk k -> applicationText "pk" $ keyToText k
    Pkh k -> applicationText "pkh" $ keyToText k
    Raw bs -> applicationText "raw" $ encodeHex bs
    Multi k ks ->
        applicationText "multi" . intercalate "," $ showText k : (keyToText <$> ks)
    SortedMulti k ks ->
        applicationText "sortedmulti" . intercalate "," $ showText k : (keyToText <$> ks)
  where
    keyToText = keyDescriptorToText net


keyDescriptorToText :: Network -> KeyDescriptor -> Text
keyDescriptorToText net (KeyDescriptor o k) = maybe mempty originText o <> definitionText
  where
    originText (Origin fp path) = "[" <> fingerprintToText fp <> pack (pathToStr path) <> "]"

    definitionText = case k of
        Pubkey (PubKeyI key c) -> encodeHex $ exportPubKey c key
        SecretKey key -> toWif net key
        XPub xpub path fam -> xPubExport net xpub <> (pack . pathToStr) path <> famText fam
        XOnlyPub key -> encodeHex $ encode key

    famText = \case
        Single -> ""
        HardKeys -> "/*'"
        SoftKeys -> "/*"


treeDescriptorToText :: Network -> TreeDescriptor -> Text
treeDescriptorToText net = \case
    TapLeaf script -> scriptDescriptorToText net script
    TapBranch left right ->
        "{" <> treeToText left <> "," <> treeToText right <> "}"
  where
    treeToText = treeDescriptorToText net
