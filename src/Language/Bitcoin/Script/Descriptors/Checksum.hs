{-# LANGUAGE ParallelListComp #-}

module Language.Bitcoin.Script.Descriptors.Checksum (
    validDescriptorChecksum,
    descriptorChecksum,
) where

import Data.Bifunctor (first)
import Data.Bits (Bits (shiftL, shiftR, testBit, xor, (.&.)))
import Data.Char (ord)
import Data.Foldable (foldl')
import Data.IntMap (IntMap)
import qualified Data.IntMap.Strict as IntMap
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Vector.Unboxed (Vector)
import qualified Data.Vector.Unboxed as Vector


-- | Test whether the textual representation of an output descriptor has the
--  given checksum.
validDescriptorChecksum :: Text -> Text -> Bool
validDescriptorChecksum desc checksum =
    case mapM (charsetFind checksumCharset) (Text.unpack checksum) of
        Nothing -> False
        Just checkSymbols ->
            1 == polymodChecksum (expandChecksum desc <> checkSymbols)


-- | Compute the checksum of the textual representation of an output descriptor
--  if possible.
descriptorChecksum :: Text -> Maybe Text
descriptorChecksum desc = Text.pack <$> sequenceA checksumChars
  where
    checksumChars = [checksumCharset `charsetGet` charsetIndex i | i <- [0 .. 7]]
    charsetIndex i = (checksum `shiftR` (5 * (7 - i))) .&. 31
    symbols = expandChecksum desc <> replicate 8 0
    checksum = 1 `xor` polymodChecksum symbols


expandChecksum :: Text -> [Word]
expandChecksum =
    reverse
        . end
        . foldl'
            ( \(gs, s) v -> case (v `shiftR` 5 : gs, v .&. 31 : s) of
                ([g2, g1, g0], s') -> ([], 9 * g0 + 3 * g1 + g2 : s')
                x -> x
            )
            mempty
        . fromMaybe []
        . mapM (charsetFind inputCharset)
        . Text.unpack
  where
    end ([g0], s) = g0 : s
    end ([g1, g0], s) = 3 * g0 + g1 : s
    end (_, s) = s


polymodChecksum :: [Word] -> Word
polymodChecksum =
    foldl'
        ( \chk value ->
            foldl'
                xor
                ((chk .&. 0x7ffffffff) `shiftL` 5 `xor` value)
                [if chk `testBit` i then g else 0 | i <- [35 ..] | g <- generator]
        )
        1
  where
    generator =
        [ 0xf5dee51989
        , 0xa9fdca3312
        , 0x1bab10e32d
        , 0x3706b1677a
        , 0x644d626ffd
        ]


data Charset = Charset
    { charToIndex :: IntMap Word
    , indexToChar :: Vector Char
    }


charsetFromString :: String -> Charset
charsetFromString s =
    let xs = [(c, i) | c <- s | i <- [0 ..]]
     in Charset
            { charToIndex = IntMap.fromList $ first ord <$> xs
            , indexToChar = Vector.fromList $ fst <$> xs
            }


charsetFind :: Charset -> Char -> Maybe Word
charsetFind set c = IntMap.lookup (ord c) $ charToIndex set


charsetGet :: Charset -> Word -> Maybe Char
charsetGet set i = indexToChar set Vector.!? fromInteger (toInteger i)


inputCharset :: Charset
inputCharset = charsetFromString "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "


checksumCharset :: Charset
checksumCharset = charsetFromString "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
