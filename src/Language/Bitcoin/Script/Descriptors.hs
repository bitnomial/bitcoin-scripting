{- | A library for working with bitcoin script descriptors. Documentation taken
 from <https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md>.
-}
module Language.Bitcoin.Script.Descriptors (
    ScriptDescriptor (..),
    KeyDescriptor (..),
    Origin (..),
    Key (..),
    KeyCollection (..),
    pubKey,
    secKey,
    keyDescPubKey,
    keyBytes,

    -- * Text representation
    descriptorToText,
    keyDescriptorToText,

    -- * Parsing
    parseDescriptor,
    descriptorParser,
    parseKeyDescriptor,
    keyDescriptorParser,
) where

import Language.Bitcoin.Script.Descriptors.Parser
import Language.Bitcoin.Script.Descriptors.Syntax
import Language.Bitcoin.Script.Descriptors.Text
