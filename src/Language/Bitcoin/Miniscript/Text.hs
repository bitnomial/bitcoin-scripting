{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Produce a text representation of Miniscript expressions
module Language.Bitcoin.Miniscript.Text (
    miniscriptToText,
) where

import Data.Text (Text)
import qualified Data.Text as Text
import Haskoin.Constants (Network)
import Haskoin.Util (encodeHex)

import Language.Bitcoin.Miniscript.Syntax (
    Miniscript (..),
    Value (..),
 )
import Language.Bitcoin.Script.Descriptors (keyDescriptorToText)
import Language.Bitcoin.Utils (applicationText, showText)

miniscriptToText :: Network -> Miniscript -> Text
miniscriptToText net = \case
    Var n -> n
    Let n e b ->
        "let " <> n <> " = " <> miniscriptToText net e <> " in " <> miniscriptToText net b
    Boolean True -> "1"
    Boolean False -> "0"
    Number w -> showText w
    Bytes b -> encodeHex b
    KeyDesc k -> keyDescriptorToText net k
    Key x -> applicationText "pk_k" $ atomicKeyDescText x
    KeyH x -> applicationText "pk_h" $ atomicKeyDescText x
    Older n -> applicationText "older" $ atomicNumberText n
    After n -> applicationText "after" $ atomicNumberText n
    Sha256 h -> applicationText "sha256" $ atomicBytesText h
    Ripemd160 h -> applicationText "ripemd160" $ atomicBytesText h
    Hash256 h -> applicationText "hash256" $ atomicBytesText h
    Hash160 h -> applicationText "hash160" $ atomicBytesText h
    AndV x (Boolean True) -> "t:" <> toText x
    OrI (Boolean False) x -> "l:" <> toText x
    OrI x (Boolean False) -> "u:" <> toText x
    AndOr x y z -> applicationText "andor" $ printList [x, y, z]
    AndV x y -> applicationText "and_v" $ printList [x, y]
    AndB x y -> applicationText "and_b" $ printList [x, y]
    OrB x y -> applicationText "or_b" $ printList [x, y]
    OrC x y -> applicationText "or_c" $ printList [x, y]
    OrD x y -> applicationText "or_d" $ printList [x, y]
    OrI x y -> applicationText "or_i" $ printList [x, y]
    Thresh k x xs ->
        applicationText "thresh" . Text.intercalate "," $ atomicNumberText k : (toText <$> (x : xs))
    Multi n xs ->
        applicationText "multi" . Text.intercalate "," $ atomicNumberText n : (atomicKeyDescText <$> xs)
    a -> ann "" a
  where
    ann as = \case
        AnnC (Key x) -> printAnn as $ applicationText "pk" $ atomicKeyDescText x
        AnnC (KeyH x) -> printAnn as $ applicationText "pkh" $ atomicKeyDescText x
        AnnA x -> ann ('a' : as) x
        AnnS x -> ann ('s' : as) x
        AnnC x -> ann ('c' : as) x
        AnnD x -> ann ('d' : as) x
        AnnV x -> ann ('v' : as) x
        AnnJ x -> ann ('j' : as) x
        AnnN x -> ann ('n' : as) x
        e -> printAnn as $ toText e

    printAnn as x
        | null as = x
        | otherwise = Text.pack (reverse as) <> ":" <> x

    printList = Text.intercalate "," . fmap toText

    toText = miniscriptToText net

    atomicNumberText = atomicText showText
    atomicBytesText = atomicText encodeHex
    atomicKeyDescText = atomicText (keyDescriptorToText net)

    atomicText f = \case
        Variable name -> name
        Lit x -> f x
