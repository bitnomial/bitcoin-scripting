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

descriptorToText :: Network -> ScriptDescriptor -> Text
descriptorToText net = \case
    Sh x -> applicationText "sh" $ pd x
    Wsh x -> applicationText "wsh" $ pd x
    Pk k -> applicationText "pk" $ pk k
    Pkh k -> applicationText "pkh" $ pk k
    Wpkh k -> applicationText "wpkh" $ pk k
    Combo k -> applicationText "combo" $ pk k
    Addr a -> applicationText "addr" . fromMaybe addrErr $ addrToText net a
    Raw bs -> applicationText "raw" $ encodeHex bs
    Multi k ks ->
        applicationText "multi" . intercalate "," $ showText k : (pk <$> ks)
    SortedMulti k ks ->
        applicationText "sortedmulti" . intercalate "," $ showText k : (pk <$> ks)
  where
    pd = descriptorToText net
    pk = keyDescriptorToText net

    addrErr = error "Unable to parse address"

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
