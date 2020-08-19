{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Text representation of policy expressions
module Language.Bitcoin.Policy.Text where

import           Data.Text                      (Text, intercalate)
import           Haskoin.Util                   (encodeHex)

import           Language.Bitcoin.Policy.Syntax
import           Language.Bitcoin.Utils         (applicationText, showText)


policyToText :: Policy -> Text
policyToText = \case
    Pk name     -> applicationText "pk" name
    After n     -> applicationText "after" $ showText n
    Older n     -> applicationText "older" $ showText n
    Sha256 h    -> applicationText "sha256" $ encodeHex h
    Hash256 h   -> applicationText "hash256" $ encodeHex h
    Ripemd160 h -> applicationText "Ripemd160" $ encodeHex h
    Hash160 h   -> applicationText "hash160" $ encodeHex h
    And p p'    -> applicationText "and" . intercalate "," $ pt <$> [p, p']
    Or b b'     -> applicationText "or" . intercalate "," $ obt <$> [b, b']
    Thresh n ps -> applicationText "thresh" . intercalate "," $ showText n : (pt <$> ps)
    where
    pt                 = policyToText
    obt (OrBranch w p) = maybe "" weightToText w <> pt p
    weightToText w     = showText w <> "@"
