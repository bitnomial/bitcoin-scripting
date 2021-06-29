{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Language.Bitcoin.Script.Utils (
    pushNumber,
    toCScriptNum,
    fromCScriptNum,
) where

import Data.Bits (clearBit, setBit, testBit)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import Haskoin (ScriptOp, intToScriptOp, opPushData)

-- | Decode a numeric stack value
fromCScriptNum :: ByteString -> Int
fromCScriptNum b
    | BS.null b = 0
    | msb == 0x80 = negate $ leWord64 b'
    | testBit msb 7 = negate . leWord64 $ BS.snoc b' (clearBit msb 7)
    | otherwise = leWord64 b
  where
    Just (b', msb) = BS.unsnoc b

-- | Encode a numeric stack value
toCScriptNum :: Int -> ByteString
toCScriptNum n
    | n == 0 = BS.empty
    | testBit msb 7 && n > 0 = BS.snoc b 0x00
    | testBit msb 7 && n < 0 = BS.snoc b 0x80
    | n < 0 = BS.snoc b' $ setBit msb 7
    | otherwise = b
  where
    (b', msb) = intLE n
    b = BS.snoc b' msb

pushNumber :: Int -> ScriptOp
pushNumber i
    | i <= 16 = intToScriptOp i
    | otherwise = opPushData $ toCScriptNum i

intLE :: Int -> (ByteString, Word8)
intLE = go mempty . abs
  where
    go b n
        | n < 0xff = (b, fromIntegral n)
        | otherwise = let (q, r) = n `quotRem` 256 in go (BS.snoc b $ fromIntegral r) q

leWord64 :: ByteString -> Int
leWord64 bs = sum $ zipWith mult (BS.unpack bs) orders
  where
    mult x y = fromIntegral x * y
    orders = (256 ^) <$> [0 :: Int ..]
