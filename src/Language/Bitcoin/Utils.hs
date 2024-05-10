{-# LANGUAGE OverloadedStrings #-}

-- |  Various parsing and printing utilities
module Language.Bitcoin.Utils (
    parens,
    brackets,
    braces,
    application,
    hex,
    comma,
    argList,
    alphanum,
    spacePadded,
    showText,
    applicationText,
    requiredContextValue,
    maybeFail,
) where

import Control.Applicative ((<|>))
import Control.Monad (void)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (Except, throwE)
import Control.Monad.Trans.Reader (ReaderT, asks)
import Data.Attoparsec.Text (Parser)
import qualified Data.Attoparsec.Text as A
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text, pack)
import Haskoin.Util (decodeHex)


parens :: Parser a -> Parser a
parens p = A.char '(' >> p <* A.char ')'


brackets :: Parser a -> Parser a
brackets p = A.char '[' >> p <* A.char ']'


braces :: Parser a -> Parser a
braces p = A.char '{' >> p <* A.char '}'


application :: Text -> Parser a -> Parser a
application fname p = A.string fname >> parens (spacePadded p)


hex :: Parser ByteString
hex = A.many1' hexChar >>= maybeFail "Invalid hex" id . decodeHex . pack
  where
    hexChar = A.satisfy $ A.inClass chars
    chars = ['0' .. '9'] <> ['a' .. 'f'] <> ['A' .. 'F']


-- | Allow for a leading comma
comma :: Parser a -> Parser a
comma p = spacePadded (A.char ',') >> p


argList :: Parser a -> Parser [a]
argList p = spacePadded p `A.sepBy` A.char ','


alphanum :: Parser Char
alphanum = A.digit <|> A.letter


spacePadded :: Parser a -> Parser a
spacePadded p = spaces >> p <* spaces


spaces :: Parser ()
spaces = void $ A.many' A.space


showText :: Show a => a -> Text
showText = pack . show


applicationText :: Text -> Text -> Text
applicationText f x = f <> "(" <> x <> ")"


maybeFail :: String -> (a -> b) -> Maybe a -> Parser b
maybeFail msg f = maybe (fail msg) (return . f)


requiredContextValue :: (r -> Map Text c) -> e -> Text -> ReaderT r (Except e) c
requiredContextValue f e name = asks (Map.lookup name . f) >>= maybe (lift $ throwE e) return
