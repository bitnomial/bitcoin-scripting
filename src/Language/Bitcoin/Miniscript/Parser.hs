{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}

module Language.Bitcoin.Miniscript.Parser
    ( miniscriptParser
    , parseMiniscript
    ) where

import           Control.Applicative                 ((<|>))
import           Control.Monad                       (void)
import           Data.Attoparsec.Text                (Parser)
import qualified Data.Attoparsec.Text                as A
import           Data.Text                           (Text, pack)
import           Haskoin.Constants                   (Network)

import           Language.Bitcoin.Miniscript.Syntax  (Miniscript (..),
                                                      Value (..))
import           Language.Bitcoin.Script.Descriptors (keyDescriptorParser)
import           Language.Bitcoin.Utils              (alphanum, application,
                                                      argList, comma, hex,
                                                      spacePadded)


parseMiniscript :: Network -> Text -> Either String Miniscript
parseMiniscript net = A.parseOnly $ miniscriptParser net


miniscriptParser :: Network -> Parser Miniscript
miniscriptParser net = annotP expression <|> expression
    where
    expression
        = keyP <|> keyCP <|> keyHP <|> keyHCP <|> olderP <|> afterP
      <|> sha256P <|> ripemd160P <|> hash256P <|> hash160P
      <|> andOrP <|> andVP <|> andBP <|> orBP <|> orCP <|> orDP <|> orIP
      <|> threshP <|> multiP
      <|> numberP <|> trueP <|> falseP <|> bytesP <|> keyDescriptorP <|> letP <|> varP

    trueP  = Boolean True  <$ A.char '1'
    falseP = Boolean False <$ A.char '0'

    numberP = Number <$> A.decimal
    bytesP  = Bytes <$> hex

    keyDescriptorP = KeyDesc <$> keyDescriptorParser net

    keyP  = Key <$> application "pk_k" atomicKeyDescP
    keyCP = AnnC . Key <$> application "pk" atomicKeyDescP

    keyHP  = KeyH <$> application "pk_h" atomicKeyDescP
    keyHCP = AnnC . KeyH <$> application "pkh" atomicKeyDescP

    olderP = Older <$> application "older" atomicNumberP
    afterP = After <$> application "after" atomicNumberP

    sha256P    = Sha256 <$> application "sha256" atomicBytesP
    ripemd160P = Ripemd160 <$> application "ripemd160" atomicBytesP
    hash256P   = Hash256 <$> application "hash256" atomicBytesP
    hash160P   = Hash160 <$> application "hash160" atomicBytesP

    andOrP = application "andor" $ AndOr <$> mp
                                         <*> comma mp
                                         <*> comma mp

    andVP  = application "and_v" $ AndV <$> mp <*> comma mp
    andBP  = application "and_b" $ AndB <$> mp <*> comma mp
    orBP   = application "or_b" $ OrB <$> mp <*> comma mp
    orCP   = application "or_c" $ OrC <$> mp <*> comma mp
    orDP   = application "or_d" $ OrD <$> mp <*> comma mp
    orIP   = application "or_i" $ OrI <$> mp <*> comma mp

    varP      = Var <$> varIdentP
    varIdentP = pack <$> A.many' (alphanum <|> A.char '_')

    letP = do
        void $ A.string "let"
        Let <$> spacePadded varIdentP
            <*> (A.char '=' >> spacePadded mp)
            <*> (A.string "in" >> spacePadded mp)

    threshP = application "thresh"
            $ Thresh <$> atomicNumberP <*> comma mp <*> comma (argList mp)

    multiP = application "multi"
           $ Multi <$> atomicNumberP <*> comma (argList atomicKeyDescP)

    atomicNumberP  = (Lit <$> A.decimal) <|> (Variable <$> varIdentP)
    atomicBytesP   = (Lit <$> hex) <|> (Variable <$> varIdentP)
    atomicKeyDescP = (Lit <$> keyDescriptorParser net) <|> (Variable <$> varIdentP)

    annotP p = do
        anns <- calcAnnotation <$> annPrefixP
        anns <$> p

    annPrefixP = A.many' (spacePadded $ A.satisfy isAnn) <* spacePadded (A.char ':')

    calcAnnotation = flip $ foldr toAnn

    toAnn = \case
        'a' -> AnnA
        's' -> AnnS
        'c' -> AnnC
        'd' -> AnnD
        'v' -> AnnV
        'j' -> AnnJ
        'n' -> AnnN
        't' -> (`AndV` Boolean True)
        'l' -> OrI (Boolean False)
        'u' -> (`OrI` Boolean False)
        _   -> error "unexpected annotation"

    isAnn = A.inClass "asctdvjnlu"

    mp = miniscriptParser net
