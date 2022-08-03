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
    descriptorToTextWithChecksum,
    keyDescriptorToText,

    -- * Parsing
    ChecksumDescriptor (..),
    ChecksumStatus (..),
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

    -- * Checksums
    descriptorChecksum,
    validDescriptorChecksum,
) where

import Language.Bitcoin.Script.Descriptors.Parser
import Language.Bitcoin.Script.Descriptors.Syntax
import Language.Bitcoin.Script.Descriptors.Text
import Language.Bitcoin.Script.Descriptors.Utils
import Language.Bitcoin.Script.Descriptors.Checksum
