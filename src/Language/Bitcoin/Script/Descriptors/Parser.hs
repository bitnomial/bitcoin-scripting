{-# LANGUAGE OverloadedStrings #-}

module Language.Bitcoin.Script.Descriptors.Parser (
    parseDescriptor,
    outputDescriptorParser,
    parseKeyDescriptor,
    keyDescriptorParser,
) where

import Control.Applicative (optional, (<|>))
import Data.Attoparsec.Text (Parser)
import qualified Data.Attoparsec.Text as A
import Data.Bool (bool)
import qualified Data.ByteString as BS
import Data.Maybe (isJust)
import Data.Text (Text, pack)
import Haskoin.Address (textToAddr)
import Haskoin.Constants (Network)
import Haskoin.Keys (
    DerivPath,
    DerivPathI (..),
    fromWif,
    importPubKey,
    wrapPubKey,
    xPubImport,
 )

import Language.Bitcoin.Script.Descriptors.Syntax
import Language.Bitcoin.Utils (
    alphanum,
    application,
    argList,
    brackets,
    comma,
    hex,
    maybeFail,
 )

parseDescriptor :: Network -> Text -> Either String OutputDescriptor
parseDescriptor net = A.parseOnly $ outputDescriptorParser net

outputDescriptorParser :: Network -> Parser OutputDescriptor
outputDescriptorParser net =
    spkP
        <|> shP
        <|> wpkhP
        <|> wshP
        <|> shwpkhP
        <|> shwshP
        <|> comboP
        <|> addrP
  where
    sdP = scriptDescriptorParser net
    keyP = keyDescriptorParser net

    spkP = ScriptPubKey <$> sdP
    shP = P2SH <$> application "sh" sdP
    wshP = P2WSH <$> application "wsh" sdP
    wpkhP = P2WPKH <$> application "wpkh" keyP
    shwpkhP = WrappedWPkh <$> (application "sh" . application "wpkh") keyP
    shwshP = WrappedWSh <$> (application "sh" . application "wsh") sdP
    comboP = Combo <$> application "combo" keyP

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
    originP = optional . brackets $ Origin <$> A.hexadecimal <*> pathP

    keyP = pubP <|> wifP <|> XPub <$> xpubP <*> pathP <*> famP

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
