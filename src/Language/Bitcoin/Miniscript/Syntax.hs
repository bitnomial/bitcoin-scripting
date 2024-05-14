{-# LANGUAGE LambdaCase #-}

-- |
--  Module: Language.Bitcoin.Miniscript.Syntax
--
--  Haskell embedding of miniscript.  See http://bitcoin.sipa.be/miniscript/ for
--  details.  Much of the documentation below is taken from this site.
module Language.Bitcoin.Miniscript.Syntax (
    Value (..),
    var,
    literal,
    Miniscript (..),
    let_,
    key,
    keyH,
    older,
    after,
    sha256,
    ripemd160,
    hash256,
    hash160,
    thresh,
    multi,
    Annotation (..),
    MiniscriptAnnotation (..),
) where

import Data.ByteString (ByteString)
import Data.Foldable (foldr')
import Data.Text (Text)
import Language.Bitcoin.Script.Descriptors.Syntax (KeyDescriptor)


data Value a = Variable Text | Lit a
    deriving (Eq, Show, Ord)


var :: Text -> Value a
var = Variable


literal :: a -> Value a
literal = Lit


-- | The Miniscript AST with the addition of key descriptors and let bindings
data Miniscript
    = Var Text
    | Let Text Miniscript Miniscript
    | Boolean Bool
    | Number Int
    | Bytes ByteString
    | KeyDesc KeyDescriptor
    | Key (Value KeyDescriptor)
    | KeyH (Value KeyDescriptor)
    | Older (Value Int)
    | After (Value Int)
    | Sha256 (Value ByteString)
    | Ripemd160 (Value ByteString)
    | Hash256 (Value ByteString)
    | Hash160 (Value ByteString)
    | AndOr Miniscript Miniscript Miniscript
    | AndV Miniscript Miniscript
    | AndB Miniscript Miniscript
    | OrB Miniscript Miniscript
    | OrC Miniscript Miniscript
    | OrD Miniscript Miniscript
    | OrI Miniscript Miniscript
    | Thresh (Value Int) Miniscript [Miniscript]
    | Multi (Value Int) [Value KeyDescriptor]
    | AnnA Miniscript
    | AnnS Miniscript
    | AnnC Miniscript
    | AnnD Miniscript
    | AnnV Miniscript
    | AnnJ Miniscript
    | AnnN Miniscript
    deriving (Eq, Show)


-- | Check a key
key :: KeyDescriptor -> Miniscript
key = AnnC . Key . literal


-- | Check a key hash
keyH :: KeyDescriptor -> Miniscript
keyH = AnnC . KeyH . literal


older :: Int -> Miniscript
older = Older . literal


after :: Int -> Miniscript
after = After . literal


sha256 :: ByteString -> Miniscript
sha256 = Sha256 . literal


ripemd160 :: ByteString -> Miniscript
ripemd160 = Ripemd160 . literal


hash256 :: ByteString -> Miniscript
hash256 = Hash256 . literal


hash160 :: ByteString -> Miniscript
hash160 = Hash160 . literal


thresh :: Int -> Miniscript -> [Miniscript] -> Miniscript
thresh k = Thresh (Lit k)


multi :: Int -> [KeyDescriptor] -> Miniscript
multi k ks = Multi (literal k) $ literal <$> ks


let_ :: [(Text, Miniscript)] -> Miniscript -> Miniscript
let_ = flip . foldr' $ uncurry Let


class MiniscriptAnnotation a where
    (.:) :: a -> Miniscript -> Miniscript


data Annotation = A | S | C | D | V | J | N | T | L | U deriving (Eq, Show, Ord, Enum)


instance MiniscriptAnnotation Annotation where
    (.:) = \case
        A -> AnnA
        S -> AnnS
        C -> AnnC
        D -> AnnD
        V -> AnnV
        J -> AnnJ
        N -> AnnN
        T -> (`AndV` Boolean True)
        L -> OrI $ Boolean True
        U -> (`OrI` Boolean False)


instance MiniscriptAnnotation a => MiniscriptAnnotation [a] where
    (.:) = flip $ foldr' (.:)
