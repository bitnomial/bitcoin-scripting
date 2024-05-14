-- | A library for working with bitcoin script descriptors. Documentation taken
--  from <https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md>.
module Language.Bitcoin.Script.Descriptors (
    -- * Descriptors
    OutputDescriptor (..),
    outputDescriptorAtIndex,
    ScriptDescriptor (..),
    scriptDescriptorAtIndex,
    TreeDescriptor (..),
    treeDescriptorAtIndex,

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
    xOnlyPubKey,
    keyBytes,
    outputDescriptorPubKeys,
    scriptDescriptorPubKeys,
    treeDescriptorPubKeys,

    -- * Text representation
    descriptorToText,
    descriptorToTextWithChecksum,
    keyDescriptorToText,
    treeDescriptorToText,

    -- * Parsing
    ChecksumDescriptor (..),
    ChecksumStatus (..),
    parseDescriptor,
    outputDescriptorParser,
    parseKeyDescriptor,
    keyDescriptorParser,
    parseTreeDescriptor,
    treeDescriptorParser,

    -- * Conversions
    descriptorAddresses,
    compile,
    compileTree,
    compileTapLeaf,
    TransactionScripts (..),
    outputDescriptorScripts,

    -- * PSBT
    toPsbtInput,
    PsbtInputError (..),

    -- * Checksums
    descriptorChecksum,
    validDescriptorChecksum,
) where

import Language.Bitcoin.Script.Descriptors.Checksum
import Language.Bitcoin.Script.Descriptors.Parser
import Language.Bitcoin.Script.Descriptors.Syntax
import Language.Bitcoin.Script.Descriptors.Text
import Language.Bitcoin.Script.Descriptors.Utils

