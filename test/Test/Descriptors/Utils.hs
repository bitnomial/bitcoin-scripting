{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.Descriptors.Utils (
    testDescriptorUtils,
) where

import qualified Data.ByteString as BS
import Data.List (sort)
import Data.Maybe (mapMaybe)
import Data.Serialize (encode)
import Haskoin (
    DerivPath,
    DerivPathI (..),
    PubKeyI (PubKeyI),
    Script (Script),
    ScriptOp (..),
    XPubKey,
    btc,
    btcRegTest,
    derivePubKey,
    opPushData,
    ripemd160,
    secKey,
    textToAddr,
    xPubImport,
 )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, (@?=))

import Language.Bitcoin.Script.Descriptors (
    Key (XPub),
    KeyCollection (..),
    KeyDescriptor (KeyDescriptor),
    OutputDescriptor (..),
    ScriptDescriptor (..),
    compile,
    descriptorAddresses,
    keyDescriptorAtIndex,
    outputDescriptorAtIndex,
    pubKey,
 )

testDescriptorUtils :: TestTree
testDescriptorUtils =
    testGroup
        "descriptor utils"
        [ testCompile
        , testAddresses
        , testKeyAtIndex
        ]

-- Address tests generated using @bitcoin-cli deriveaddresses@
testAddresses :: TestTree
testAddresses =
    testGroup
        "addresses"
        [ testP2PKH
        , testP2SH
        , testP2WPKH
        , testP2WSH
        , testWrappedWPhk
        , testWrappedWSh
        , testCombo
        ]

testKeyAtIndex :: TestTree
testKeyAtIndex =
    testGroup
        "keyAtIndex"
        [ testKeyDescriptorAtIndex
        , testOutputDescriptorAtIndex
        ]

testP2PKH :: TestTree
testP2PKH = testCase "P2PKH" $ descriptorAddresses example @?= [expected]
  where
    example = ScriptPubKey . Pkh $ pubKey key0
    Just expected = textToAddr btcRegTest "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"

testP2SH :: TestTree
testP2SH = testCase "P2SH" $ descriptorAddresses example @?= [expected]
  where
    example = P2SH $ SortedMulti 2 ks
    Just expected = textToAddr btcRegTest "2MuFU6ZyBLtDNadMA6RnwJdXGWUSUaoKLeS"
    ks = pubKey <$> take 3 testPubKeys

testP2WPKH :: TestTree
testP2WPKH = testCase "P2WPKH" $ descriptorAddresses example @?= [expected]
  where
    example = P2WPKH $ pubKey key0
    Just expected = textToAddr btcRegTest "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

testP2WSH :: TestTree
testP2WSH = testCase "P2WSH" $ descriptorAddresses example @?= [expected]
  where
    example = P2WSH . Pkh $ pubKey key0
    Just expected = textToAddr btcRegTest "bcrt1q8a9wr6e7whe40py3sywj066euga9zt8ep3emz0r2e4zfna7y629sq89pz7"

testWrappedWPhk :: TestTree
testWrappedWPhk = testCase "Wrapped P2WPKH" $ descriptorAddresses example @?= [expected]
  where
    example = WrappedWPkh $ pubKey key0
    Just expected = textToAddr btcRegTest "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN"

testWrappedWSh :: TestTree
testWrappedWSh = testCase "Wrapped P2WSH" $ descriptorAddresses example @?= [expected]
  where
    example = WrappedWSh $ SortedMulti 2 ks
    ks = pubKey <$> take 3 testPubKeys
    Just expected = textToAddr btcRegTest "2NBbyaKyqn2AhMzSnQZrVPAW46KW1it9v7r"

testCombo :: TestTree
testCombo = testCase "Combo" $ sort (descriptorAddresses example) @?= sort expected
  where
    example = Combo $ pubKey key0
    Just expected =
        traverse
            (textToAddr btcRegTest)
            [ "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"
            , "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
            , "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN"
            ]

testCompile :: TestTree
testCompile = testGroup "compile" [testPk, testPkh, testMulti, testSortedMulti]

testPk :: TestTree
testPk = testCase "Pk" $ compile example @?= Just expected
  where
    example = Pk $ pubKey key0
    expected = Script [opPushData (encode key0), OP_CHECKSIG]

testPkh :: TestTree
testPkh = testCase "Pkh" $ compile example @?= Just expected
  where
    example = Pkh $ pubKey key0
    expected = Script [OP_DUP, OP_HASH160, opPushData (encode keyHash), OP_EQUALVERIFY, OP_CHECKSIG]
    keyHash = ripemd160 $ encode key0

testMulti :: TestTree
testMulti = testCase "Multi" $ compile example @?= Just expected
  where
    example = Multi 2 $ pubKey <$> ks
    expected = Script [OP_2, opPushData (encode k0), opPushData (encode k1), opPushData (encode k2), OP_3, OP_CHECKMULTISIG]
    ks@[k0, k1, k2] = take 3 testPubKeys

testSortedMulti :: TestTree
testSortedMulti = testCase "SortedMulti" $ compile example @?= Just expected
  where
    example = SortedMulti 2 $ pubKey <$> ks
    expected = Script [OP_2, opPushData k0, opPushData k1, opPushData k2, OP_3, OP_CHECKMULTISIG]
    ks = take 3 testPubKeys
    [k0, k1, k2] = sort $ encode <$> ks

testKeyDescriptorAtIndex :: TestTree
testKeyDescriptorAtIndex = testCase "keyDescriptorAtIndex" $ do
    keyDescriptorAtIndex 5 keyFamA @?= keyA
    keyDescriptorAtIndex 5 keyFamB @?= keyB
    keyDescriptorAtIndex 5 keyC @?= keyC
  where
    keyFamA = KeyDescriptor Nothing $ XPub someXPubA basePath HardKeys
    keyA = KeyDescriptor Nothing $ XPub someXPubA (basePath :| 5) Single

    keyFamB = KeyDescriptor Nothing $ XPub someXPubA basePath SoftKeys
    keyB = KeyDescriptor Nothing $ XPub someXPubA (basePath :/ 5) Single

    keyC = KeyDescriptor Nothing $ XPub someXPubA basePath Single

testOutputDescriptorAtIndex :: TestTree
testOutputDescriptorAtIndex = testCase "outputDescriptorAtIndex" $ do
    outputDescriptorAtIndex 5 descFamA @?= descA
    outputDescriptorAtIndex 5 descFamB @?= descB
    outputDescriptorAtIndex 5 descFamC @?= descC
  where
    descFamA = P2SH $ SortedMulti 2 [keyFamA, keyFamB]
    descA = P2SH $ SortedMulti 2 [keyA, keyB]

    descFamB = P2WSH $ Pkh keyFamB
    descB = P2WSH $ Pkh keyB

    descFamC = P2WPKH keyFamA
    descC = P2WPKH keyA

    keyFamA = KeyDescriptor Nothing $ XPub someXPubA basePath HardKeys
    keyA = KeyDescriptor Nothing $ XPub someXPubA (basePath :| 5) Single

    keyFamB = KeyDescriptor Nothing $ XPub someXPubB basePath HardKeys
    keyB = KeyDescriptor Nothing $ XPub someXPubB (basePath :| 5) Single

key0 :: PubKeyI
testPubKeys :: [PubKeyI]
testPubKeys@(key0 : _) = (`PubKeyI` True) . derivePubKey <$> mapMaybe (secKey . mkSecKey) [1 .. 255]
  where
    mkSecKey i = BS.pack $ replicate 31 0 <> [i]

someXPubA, someXPubB :: XPubKey
Just someXPubA = xPubImport btc "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
Just someXPubB = xPubImport btc "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

basePath :: DerivPath
basePath = Deriv :| 1500
