{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Convert descriptors to text
module Language.Bitcoin.Script.Descriptors.Text (
    descriptorToText,
    keyDescriptorToText,
) where

import Data.ByteString.Builder (
    toLazyByteString,
    word32BE,
 )
import Data.ByteString.Lazy (toStrict)
import Data.Maybe (fromMaybe)
import Data.Text (
    Text,
    intercalate,
    pack,
 )
import Haskoin.Address (addrToText)
import Haskoin.Constants (Network)
import Haskoin.Keys (
    PubKeyI (..),
    exportPubKey,
    pathToStr,
    toWif,
    xPubExport,
 )
import Haskoin.Util (encodeHex)

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
    Addr a -> applicationText "addr" . fromMaybe addrErr $ addrToText net a
  where
    sdToText = scriptDescriptorToText net
    keyToText = keyDescriptorToText net

    addrErr = error "Unable to parse address"

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
    originText (Origin fp path) = "[" <> fingerprintText fp <> pack (pathToStr path) <> "]"

    definitionText = case k of
        Pubkey (PubKeyI key c) -> encodeHex $ exportPubKey c key
        SecretKey key -> toWif net key
        XPub xpub path fam -> xPubExport net xpub <> (pack . pathToStr) path <> famText fam

    famText = \case
        Single -> ""
        HardKeys -> "/*'"
        SoftKeys -> "/*"

    fingerprintText = encodeHex . toStrict . toLazyByteString . word32BE
