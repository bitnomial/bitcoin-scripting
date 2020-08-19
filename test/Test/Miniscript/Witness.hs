{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-incomplete-patterns #-}

module Test.Miniscript.Witness
    ( witnessTests
    ) where

import           Data.ByteString                     (ByteString)
import           Data.Serialize                      (encode)
import           Data.Text                           (Text)
import           Haskoin.Crypto                      (ripemd160, sha256,
                                                      signHash)
import           Haskoin.Keys                        (PubKeyI, secKeyData)
import           Haskoin.Script                      (Script (..),
                                                      ScriptOp (..),
                                                      TxSignature (..),
                                                      encodeTxSig, opPushData,
                                                      sigHashAll)
import           Haskoin.Util.Arbitrary.Keys         (arbitraryKeyPair)
import           Haskoin.Util.Arbitrary.Util         (arbitraryBSn)
import           Test.Tasty                          (TestTree, testGroup)
import           Test.Tasty.QuickCheck               (Gen, Property, Testable,
                                                      forAll, (===))

import           Language.Bitcoin.Miniscript         (Miniscript (..), let_)
import           Language.Bitcoin.Miniscript.Witness (ChainState (..),
                                                      SatisfactionError (..),
                                                      Signature (..),
                                                      emptyChainState, preimage,
                                                      satisfactionContext,
                                                      satisfy, signature)
import           Language.Bitcoin.Script.Descriptors (pubKey)
import           Test.Example                        (Example (..),
                                                      testExampleProperty)
import qualified Test.Miniscript.Examples            as E
import           Test.Utils                          (forAllLabeled, pr23)


witnessTests :: TestTree
witnessTests = testGroup "witness" examples
    where
    examples =
        [ example1
        , example2
        , example3
        , example4
        , example5
        , example6
        , example7
        , example8
        , example9
        , example10
        ]


pushKey :: PubKeyI -> ScriptOp
pushKey = opPushData . encode


pushSig :: Signature -> ScriptOp
pushSig (Signature s sh) = opPushData . encodeTxSig $ TxSignature s sh


forKeys :: Testable p => [Text] -> Miniscript -> ([(PubKeyI, Signature)] -> Miniscript -> p) -> Property
forKeys ls scr k = forAllLabeled arbKeySig mkRow ls mkProp
    where
    mkRow label (pk, s) = (label, pk, s)
    mkProp xs = k (pr23 <$> xs) $ let_ (binding <$> xs) scr
    binding (l, pk, _) = (l, KeyDesc $ pubKey pk)


arbKeySig :: Gen (PubKeyI, Signature)
arbKeySig = repack <$> arbitraryKeyPair
    where
    repack (sk, pk) = (pk, mkSig $ secKeyData sk)

    mkSig s = Signature (signHash s $ sha256 msg) sigHashAll

    msg :: ByteString
    msg = "arbKeySig"


testExample
    :: Testable p
    => Example Miniscript
    -> [Text]
    -> ([(PubKeyI, Signature)] -> Miniscript -> p)
    -> TestTree
testExample e ls = testExampleProperty e . forKeys ls (script e)


example1 :: TestTree
example1 = testExample E.example1 ["key_1"] test
    where
    test [(k, s)] scr = satisfy emptyChainState (signature k s) scr === Right (Script [pushSig s])


example2 :: TestTree
example2 = testExample E.example2 ["key_1", "key_2"] test
    where
    test xs scr = satisfy emptyChainState (context xs) scr === Right (expected xs)

    expected ((_, s) : _) = Script [OP_0, pushSig s]
    context (x : _)       = uncurry signature x


example3 :: TestTree
example3 = testExample E.example3 ["key_likely", "key_unlikely"] test
    where
    test xs scr = satisfy emptyChainState (context xs) scr === Right (expected xs)

    expected (_ : (k, s): _) = Script [pushSig s, pushKey k, OP_0]
    context (_ : x : _)      = uncurry signature x


example4 :: TestTree
example4 = testExample E.example4 ["key_user", "key_service"] test
    where
    test xs scr = satisfy chainState (context xs) scr === Right (expected xs)

    expected ((_, s) : _) = Script [OP_0, pushSig s]
    context (x : _)       = uncurry signature x

    chainState = ChainState { blockHeight = Nothing, utxoAge = Just 20000 }


example5 :: TestTree
example5 = testExample E.example5 ["key_1", "key_2", "key_3"] test
    where
    test xs scr = result xs scr === Right (expected xs)

    expected [(_, s1), _, (_, s3)] = Script [OP_1, pushSig s3, OP_0, pushSig s1]
    result [x1, _, x3] scr         = satisfy chainState (context x1 x3) scr
    context (k1, s1) (k3, s3)      = signature k1 s1 <> signature k3 s3

    chainState = ChainState { blockHeight = Nothing, utxoAge = Just 13000 }


example6 :: TestTree
example6 = testExample E.example6 ["key_local", "key_revocation"] test
    where
    test xs scr = result xs scr === Right (expected xs)

    expected [_, (_, s2)] = Script [pushSig s2, OP_0]
    result xs scr = satisfy chainState (context xs) scr
    context = foldMap (uncurry signature)

    chainState = ChainState { blockHeight = Nothing, utxoAge = Just 100 }


hashBinding :: ByteString -> Miniscript -> Miniscript
hashBinding bs = let_ [("H", Bytes . encode $ ripemd160 bs)]


example7 :: TestTree
example7 = testExample E.example7 ["key_local", "key_remote", "key_revocation"] test
    where
    test xs scr = forAll (arbitraryBSn 32) $ \bs ->
        satisfy chainState (context xs bs) (hashBinding bs scr) === Right (expected xs bs)

    expected [_, (_, s), _] bs = Script [opPushData bs, OP_0, pushSig s, OP_0]
    context [_, x, _] bs = uncurry signature x <> preimage (encode $ ripemd160 bs) bs

    chainState = ChainState { blockHeight = Nothing, utxoAge = Just 2000 }


example8 :: TestTree
example8 = testExample E.example8 ["key_local", "key_remote", "key_revocation"] test
    where
    test xs scr = forAll (arbitraryBSn 32) $ \bs ->
        satisfy chainState (context xs bs) (hashBinding bs scr) === Right (expected xs bs)

    expected [(kl, sl), (_, sr), _] bs = Script [opPushData bs, pushSig sl, pushKey kl, OP_1, pushSig sr]
    context [l, r, _] bs = satisfactionContext [(encode $ ripemd160 bs, bs)] [l, r]

    chainState = ChainState { blockHeight = Nothing, utxoAge = Just 6 }


example9 :: TestTree
example9 = testExample E.example9 [] test
    where
    test _ scr = satisfy chainState mempty scr === Left Impossible
    chainState = ChainState { blockHeight = Nothing, utxoAge = Just 100 }


example10 :: TestTree
example10 = testExample E.example10 ["A", "B", "C", "D", "E", "F", "G", "H"] test
    where
    test xs scr = satisfy chainState (context xs) scr === Right (expected xs)

    expected xs = Script $ OP_0 : drop 1 (foldMap pushPkhSig (reverse $ drop 5 xs)) <> replicate 5 OP_0
    context xs  = foldMap (uncurry signature) . take 2 $ drop 5 xs

    chainState = ChainState { blockHeight = Nothing, utxoAge = Just 20000 }

    pushPkhSig (k, s) = [pushSig s, pushKey k]
