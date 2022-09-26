{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Test.Descriptors.Utils (
    testDescriptorUtils,
) where

import qualified Data.ByteString as BS
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (serialize)
import qualified Data.HashMap.Strict as HM
import Data.List (sort)
import Data.Maybe (fromJust, mapMaybe)
import Data.Serialize (encode)
import Haskoin (
    DerivPath,
    DerivPathI (..),
    MAST (MASTBranch, MASTLeaf),
    OutPoint (OutPoint),
    PubKeyI (PubKeyI, pubKeyPoint),
    Script (Script),
    ScriptOp (..),
    ScriptOutput (..),
    XOnlyPubKey (XOnlyPubKey),
    XPubKey,
    addressHash,
    btc,
    btcRegTest,
    buildTx,
    decodeHex,
    derivePubKey,
    derivePubPath,
    emptyInput,
    encodeOutput,
    inputHDKeypaths,
    inputRedeemScript,
    inputWitnessScript,
    mastCommitment,
    nonWitnessUtxo,
    opPushData,
    pathToList,
    ripemd160,
    secKey,
    textToAddr,
    toP2SH,
    toP2WSH,
    toSoft,
    txOut,
    witnessUtxo,
    xPubFP,
    xPubImport,
    xPubKey,
 )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, testCaseSteps, (@?=))

import Language.Bitcoin.Script.Descriptors (
    Key (XPub),
    KeyCollection (..),
    KeyDescriptor (KeyDescriptor),
    OutputDescriptor (..),
    ScriptDescriptor (..),
    TreeDescriptor (TapBranch, TapLeaf),
    compile,
    compileTapLeaf,
    compileTree,
    descriptorAddresses,
    keyDescriptorAtIndex,
    outputDescriptorAtIndex,
    pubKey,
    toPsbtInput,
 )

testDescriptorUtils :: TestTree
testDescriptorUtils =
    testGroup
        "descriptor utils"
        [ testCompile
        , testCompileTree
        , testCompileTapLeaf
        , testAddresses
        , testKeyAtIndex
        , testToPsbtInput
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
        , testP2TR
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

testP2TR :: TestTree
testP2TR =
    testGroup
        "P2TR"
        [ testP2TRInternalKeyOnly
        , testP2TRSingleScriptPath
        , testP2TRMultiScriptPaths
        ]

testP2TRInternalKeyOnly :: TestTree
testP2TRInternalKeyOnly =
    testCase "P2TR internal key only" $
        descriptorAddresses example @?= [expected]
  where
    example = P2TR (pubKey key0) Nothing
    Just expected =
        textToAddr
            btcRegTest
            "bcrt1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssm803es"

testP2TRSingleScriptPath :: TestTree
testP2TRSingleScriptPath =
    testCase "P2TR tree (single script path)" $
        descriptorAddresses example @?= [expected]
  where
    example = P2TR (pubKey key0) $ Just $ TapLeaf $ Pk $ pubKey key1
    Just expected =
        textToAddr
            btcRegTest
            "bcrt1pg44et8f66qnjn5fd0hu6dnnx7tczqslmt3dkzpccjlzeg99psshqfkkdep"
    _ : key1 : _ = testPubKeys

testP2TRMultiScriptPaths :: TestTree
testP2TRMultiScriptPaths =
    testCase "P2TR tree (multi script paths)" $
        descriptorAddresses example @?= [expected]
  where
    example =
        P2TR (pubKey key0) $
            Just $
                TapBranch
                    (TapLeaf $ Pk $ pubKey key1)
                    (TapLeaf $ Pk $ pubKey key2)
    Just expected =
        textToAddr
            btcRegTest
            "bcrt1pprj5dr4rgrw835zyx8ncp9qe54n3ljcgcft0tw9mlj657udee6nq47mg8u"
    _ : key1 : key2 : _ = testPubKeys

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

testCompileTree :: TestTree
testCompileTree = testGroup "testCompileTree" [testTapLeaf, testTapBranch]

testTapLeaf :: TestTree
testTapLeaf =
    testCase "TapLeaf" $
        (mastCommitment <$> compileTree example)
            @?= Just (mastCommitment expected)
  where
    example = TapLeaf $ Pk $ pubKey key0
    expected =
        MASTLeaf 0xc0 $
            Script
                [ opPushData (encode $ XOnlyPubKey $ pubKeyPoint $ key0)
                , OP_CHECKSIG
                ]

testTapBranch :: TestTree
testTapBranch =
    testCase "TapBranch" $
        (mastCommitment <$> compileTree example)
            @?= Just (mastCommitment expected)
  where
    example =
        TapBranch
            (TapLeaf $ Pk $ pubKey key0)
            (TapLeaf $ Pk $ pubKey key1)
    expected =
        MASTBranch
            ( MASTLeaf 0xc0 $
                Script
                    [ opPushData (encode $ XOnlyPubKey $ pubKeyPoint $ key1)
                    , OP_CHECKSIG
                    ]
            )
            ( MASTLeaf 0xc0 $
                Script
                    [ opPushData (encode $ XOnlyPubKey $ pubKeyPoint $ key0)
                    , OP_CHECKSIG
                    ]
            )
    _ : key1 : _ = testPubKeys

testCompileTapLeaf :: TestTree
testCompileTapLeaf = testGroup "testCompileTapLeaf" [testTapLeafPk]

testTapLeafPk :: TestTree
testTapLeafPk = testCase "Pk" $ compileTapLeaf example @?= Just expected
  where
    example = Pk $ pubKey key0
    expected =
        Script
            [ opPushData (encode $ XOnlyPubKey $ pubKeyPoint $ key0)
            , OP_CHECKSIG
            ]

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
    outputDescriptorAtIndex 5 descFamD @?= descD
  where
    descFamA = P2SH $ SortedMulti 2 [keyFamA, keyFamB]
    descA = P2SH $ SortedMulti 2 [keyA, keyB]

    descFamB = P2WSH $ Pkh keyFamB
    descB = P2WSH $ Pkh keyB

    descFamC = P2WPKH keyFamA
    descC = P2WPKH keyA

    descFamD = P2TR keyFamA (Just $ TapLeaf $ Pk $ keyFamB)
    descD = P2TR keyA (Just $ TapLeaf $ Pk $ keyB)

    keyFamA = KeyDescriptor Nothing $ XPub someXPubA basePath HardKeys
    keyA = KeyDescriptor Nothing $ XPub someXPubA (basePath :| 5) Single

    keyFamB = KeyDescriptor Nothing $ XPub someXPubB basePath HardKeys
    keyB = KeyDescriptor Nothing $ XPub someXPubB (basePath :| 5) Single

testToPsbtInput :: TestTree
testToPsbtInput = testCaseSteps "toPsbtInput" $ \step -> do
    step "P2PKH"
    toPsbtInput p2pkhTx 0 p2pkhDescriptor @?= Right expectedP2pkhInput

    step "P2SH-MS"
    toPsbtInput p2shMsTx 0 p2shMsDescriptor @?= Right expectedP2shMsInput

    step "P2SH-WPKH"
    toPsbtInput p2shWpkhTx 0 p2shWpkhDescriptor @?= Right expectedP2shWpkhInput

    step "P2SH-WSH-MS"
    toPsbtInput p2shWshMsTx 0 p2shWshMsDescriptor @?= Right expectedP2shWshMsInput

    step "P2WPKH"
    toPsbtInput wpkhTx 0 wpkhDescriptor @?= Right expectedWpkhInput

    step "P2WSH-MS"
    toPsbtInput wshMsTx 0 wshMsDescriptor @?= Right expectedWshMsInput

    step "P2TR"
    toPsbtInput trTx 0 trDescriptor @?= Right expectedTrInput
  where
    p2pkhTx = buildTx [outPoint] [(PayPKHash hashA, 1_000_000)]
    p2pkhDescriptor = ScriptPubKey $ Pkh keyA
    expectedP2pkhInput =
        emptyInput
            { nonWitnessUtxo = Just p2pkhTx
            , inputHDKeypaths = hdKeypathA
            }

    p2shMsTx = buildTx [outPoint] [(msScriptOutput, 1_000_000)]
    p2shMsDescriptor = P2SH msDescriptor
    expectedP2shMsInput =
        emptyInput
            { nonWitnessUtxo = Just p2shMsTx
            , inputRedeemScript = Just $ encodeOutput msScriptOutput
            , inputHDKeypaths = hdKeypathA <> hdKeypathB
            }
    msScriptOutput = PayMulSig [pubKeyA, pubKeyB] 1
    msDescriptor = Multi 1 [keyA, keyB]

    keyA = KeyDescriptor Nothing $ XPub someXPubA path Single
    pubKeyA = (`PubKeyI` True) . xPubKey $ derivePubPath softPath someXPubA
    hashA = addressHash . runPutS $ serialize pubKeyA
    hdKeypathA = HM.singleton pubKeyA (xPubFP someXPubA, pathToList path)

    keyB = KeyDescriptor Nothing $ XPub someXPubB path Single
    pubKeyB = (`PubKeyI` True) . xPubKey $ derivePubPath softPath someXPubB
    hdKeypathB = HM.singleton pubKeyB (xPubFP someXPubB, pathToList path)

    p2shWpkhDescriptor = WrappedWPkh keyA
    p2shWpkhTx = buildTx [outPoint] [(p2shWpkhScriptOutput, 1_000_000)]
    expectedP2shWpkhInput =
        emptyInput
            { witnessUtxo = Just $ (head . txOut) p2shWpkhTx
            , inputRedeemScript = Just $ encodeOutput wpkhScriptOutputA
            , inputHDKeypaths = hdKeypathA
            }
    p2shWpkhScriptOutput = toP2SH $ encodeOutput wpkhScriptOutputA
    wpkhScriptOutputA = PayWitnessPKHash hashA

    p2shWshMsTx = buildTx [outPoint] [(p2shWshMsOutput, 1_000_000)]
    p2shWshMsDescriptor = WrappedWSh msDescriptor
    expectedP2shWshMsInput =
        emptyInput
            { witnessUtxo = Just $ (head . txOut) p2shWshMsTx
            , inputRedeemScript = Just $ encodeOutput wshMsOutput
            , inputWitnessScript = Just $ encodeOutput msScriptOutput
            , inputHDKeypaths = hdKeypathA <> hdKeypathB
            }
    p2shWshMsOutput = toP2SH $ encodeOutput wshMsOutput
    wshMsOutput = toP2WSH $ encodeOutput msScriptOutput

    wpkhTx = buildTx [outPoint] [(PayWitnessPKHash hashA, 1_000_000)]
    wpkhDescriptor = P2WPKH keyA
    expectedWpkhInput =
        emptyInput
            { witnessUtxo = Just . head $ txOut wpkhTx
            , inputHDKeypaths = hdKeypathA
            }
    wshMsTx = buildTx [outPoint] [(wshMsOutput, 1_000_000)]
    wshMsDescriptor = P2WSH msDescriptor
    expectedWshMsInput =
        emptyInput
            { witnessUtxo = Just $ (head . txOut) wshMsTx
            , inputWitnessScript = Just $ encodeOutput msScriptOutput
            , inputHDKeypaths = hdKeypathA <> hdKeypathB
            }

    trTx = buildTx [outPoint] [(trOut, 1_000_000)]
    trOut =
        PayWitness 0x01 $
            fromJust $
                decodeHex $
                    "da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21"
    trDescriptor = P2TR keyA Nothing
    expectedTrInput =
        emptyInput
            { witnessUtxo = Just $ (head . txOut) trTx
            , inputHDKeypaths = hdKeypathA
            }

    outPoint = OutPoint "0000000000000000000000000000000000000000000000000000000000000000" 0
    path = Deriv :/ 1 :: DerivPath
    Just softPath = toSoft path

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
