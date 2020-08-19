{-# LANGUAGE OverloadedStrings #-}

module Language.Bitcoin.Policy.Parser
    ( parsePolicy
    , policyParser
    ) where

import           Control.Applicative            (optional, (<|>))
import           Data.Attoparsec.Text           (Parser)
import qualified Data.Attoparsec.Text           as A
import           Data.Text                      (Text, pack)

import           Language.Bitcoin.Policy.Syntax
import           Language.Bitcoin.Utils         (alphanum, application, argList,
                                                 comma, hex, spacePadded)


parsePolicy :: Text -> Either String Policy
parsePolicy = A.parseOnly policyParser


policyParser :: Parser Policy
policyParser
    = pkP <|> afterP <|> olderP
  <|> sha256P <|> hash256P <|> ripemd160P <|> hash160P
  <|> andP <|> orP <|> threshP

    where
    pkP = Pk <$> application "pk" nameP

    afterP = After <$> application "after" A.decimal
    olderP = Older <$> application "older" A.decimal

    sha256P    = Sha256 <$> application "sha256" hex
    hash256P   = Hash256 <$> application "hash256" hex
    ripemd160P = Ripemd160 <$> application "ripemd160" hex
    hash160P   = Hash160 <$> application "hash160" hex

    andP = application "and" $ And <$> policyP <*> comma policyP

    orP     = application "or" $ Or <$> branchP <*> comma branchP
    branchP = OrBranch <$> optional weightP <*> policyP
    weightP = A.decimal <* spacePadded (A.char '@')

    threshP = application "thresh" $ Thresh <$> A.decimal <*> comma (argList policyP)

    nameP   = pack <$> A.many1' alphanum
    policyP = policyParser
