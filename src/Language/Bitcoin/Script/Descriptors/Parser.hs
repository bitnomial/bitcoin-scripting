{-# LANGUAGE OverloadedStrings #-}

module Language.Bitcoin.Script.Descriptors.Parser (
    ChecksumDescriptor (..),
    ChecksumStatus (..),
    parseDescriptor,
    outputDescriptorParser,
    parseKeyDescriptor,
    keyDescriptorParser,
    parseTreeDescriptor,
    treeDescriptorParser,
) where

import Control.Applicative (optional, (<|>))
import Data.Attoparsec.Text (Parser, char, count, match)
import qualified Data.Attoparsec.Text as A
import Data.Bool (bool)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe, isJust)
import Data.Text (Text, pack)
import Haskoin (
    DerivPath,
    DerivPathI (..),
    Network,
    fromWif,
    importPubKey,
    textToAddr,
    textToFingerprint,
    wrapPubKey,
    xPubImport,
 )

import Data.Serialize (decode)
import qualified Data.Text as Text
import Language.Bitcoin.Script.Descriptors.Checksum (
    descriptorChecksum,
    validDescriptorChecksum,
 )
import Language.Bitcoin.Script.Descriptors.Syntax
import Language.Bitcoin.Utils (
    alphanum,
    application,
    argList,
    braces,
    brackets,
    comma,
    hex,
    maybeFail,
 )


-- | An 'OutputDescriptor' with checksum details
data ChecksumDescriptor = ChecksumDescriptor
    { descriptor :: OutputDescriptor
    -- ^ The output descriptor
    , checksumStatus :: ChecksumStatus
    -- ^ The status of the output descriptor's checksum
    , expectedChecksum :: Text
    -- ^ The expected checksum for the output descriptor
    }
    deriving (Eq, Show)


-- | The status of an output descriptor's checksum
data ChecksumStatus
    = -- | Checksum provided is valid
      Valid
    | -- | Checksum provided is invalid
      Invalid
        -- | The invalid checksum
        Text
    | -- | Checksum is not provided
      Absent
    deriving (Eq, Show)


parseDescriptor :: Network -> Text -> Either String ChecksumDescriptor
parseDescriptor = A.parseOnly . outputDescriptorParser


outputDescriptorParser :: Network -> Parser ChecksumDescriptor
outputDescriptorParser net =
    checksumParser $
        spkP
            <|> shP
            <|> wpkhP
            <|> wshP
            <|> shwpkhP
            <|> shwshP
            <|> comboP
            <|> trP
            <|> addrP
  where
    sdP = scriptDescriptorParser net
    keyP = keyDescriptorParser net
    treeP = treeDescriptorParser net

    spkP = ScriptPubKey <$> sdP
    shP = P2SH <$> application "sh" sdP
    wshP = P2WSH <$> application "wsh" sdP
    wpkhP = P2WPKH <$> application "wpkh" keyP
    shwpkhP = WrappedWPkh <$> (application "sh" . application "wpkh") keyP
    shwshP = WrappedWSh <$> (application "sh" . application "wsh") sdP
    comboP = Combo <$> application "combo" keyP
    trP = application "tr" $ P2TR <$> keyP <*> optional (comma treeP)

    addrP =
        application "addr" (A.manyTill A.anyChar $ A.char ')')
            >>= maybeFail "descriptorParser: unable to parse address" Addr . textToAddr net . pack


scriptDescriptorParser :: Network -> Parser ScriptDescriptor
scriptDescriptorParser net = pkP <|> pkhP <|> rawP <|> multiP <|> sortedMultiP
  where
    kp = keyDescriptorParser net

    rawP = Raw <$> application "raw" hex
    pkP = Pk <$> application "pk" kp
    pkhP = Pkh <$> application "pkh" kp

    multiP = application "multi" $ Multi <$> A.decimal <*> comma keyList
    sortedMultiP = application "sortedmulti" $ SortedMulti <$> A.decimal <*> comma keyList

    keyList = argList kp


parseKeyDescriptor :: Network -> Text -> Either String KeyDescriptor
parseKeyDescriptor net = A.parseOnly $ keyDescriptorParser net


keyDescriptorParser :: Network -> Parser KeyDescriptor
keyDescriptorParser net = KeyDescriptor <$> originP <*> keyP
  where
    originP = optional . brackets $ Origin <$> fingerprintP <*> pathP

    fingerprintP =
        A.take 8
            >>= either fail pure . textToFingerprint

    keyP = pubP <|> xOnlyPubP <|> wifP <|> XPub <$> xpubP <*> pathP <*> famP

    xOnlyPubP = do
        bs <- hex
        either fail (return . XOnlyPub) $ decode bs

    pubP = do
        bs <- hex
        maybeFail "Unable to parse pubkey" (toPubKey bs) $ importPubKey bs

    toPubKey bs = Pubkey . wrapPubKey (isCompressed bs)
    isCompressed bs = BS.length bs == 33

    wifP = A.many1' alphanum >>= maybeFail "Unable to parse WIF secret key" SecretKey . fromWif net . pack
    xpubP = A.many1' alphanum >>= maybeFail "Unable to parse xpub" id . xPubImport net . pack

    famP = (HardKeys <$ A.string "/*'") <|> (SoftKeys <$ A.string "/*") <|> pure Single


pathP :: Parser DerivPath
pathP = go Deriv
  where
    go d = maybe (return d) go =<< optional (componentP d)

    componentP d = do
        _ <- A.char '/'
        n <- A.decimal
        isHard <- isJust <$> optional (A.char '\'' <|> A.char 'h')
        return $ bool (d :/) (d :|) isHard n


parseTreeDescriptor :: Network -> Text -> Either String TreeDescriptor
parseTreeDescriptor net = A.parseOnly $ treeDescriptorParser net


treeDescriptorParser :: Network -> Parser TreeDescriptor
treeDescriptorParser net =
    TapLeaf <$> scriptDescriptorParser net
        <|> braces (TapBranch <$> treeParser <*> comma treeParser)
  where
    treeParser = treeDescriptorParser net


checksumParser :: Parser OutputDescriptor -> Parser ChecksumDescriptor
checksumParser p = do
    (input, desc) <- match p
    actual <- fmap (fromMaybe "") . optional $ do
        _ <- char '#'
        Text.pack <$> count 8 alphanum
    let status = case actual of
            "" -> Absent
            _
                | input `validDescriptorChecksum` actual -> Valid
                | otherwise -> Invalid actual
        expected = fromMaybe "" $ descriptorChecksum input
    return $ ChecksumDescriptor desc status expected
