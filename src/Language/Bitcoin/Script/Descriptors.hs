{- | A library for working with bitcoin script descriptors. Documentation taken
 from <https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md>.
-}
module Language.Bitcoin.Script.Descriptors (
    -- * Descriptors
    OutputDescriptor (..),
    outputDescriptorAtIndex,
    ScriptDescriptor (..),
    scriptDescriptorAtIndex,

    -- * Keys
    KeyDescriptor (..),
    Origin (..),
    Key (..),
    KeyCollection (..),
    isDefinite,
    keyAtIndex,
    keyDescriptorAtIndex,
    keyDescPubKey,
    pubKey,
    secKey,
    keyBytes,
    outputDescriptorPubKeys,
    scriptDescriptorPubKeys,

    -- * Text representation
    descriptorToText,
    keyDescriptorToText,

    -- * Parsing
    parseDescriptor,
    outputDescriptorParser,
    parseKeyDescriptor,
    keyDescriptorParser,

    -- * Conversions
    descriptorAddresses,
    compile,
    TransactionScripts (..),
    outputDescriptorScripts,

    -- * PSBT
    toPsbtInput,
    PsbtInputError (..),
) where

import Language.Bitcoin.Script.Descriptors.Parser
import Language.Bitcoin.Script.Descriptors.Syntax
import Language.Bitcoin.Script.Descriptors.Text
import Language.Bitcoin.Script.Descriptors.Utils
