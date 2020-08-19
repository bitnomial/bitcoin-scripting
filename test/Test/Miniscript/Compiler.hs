{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -Wno-incomplete-patterns #-}

module Test.Miniscript.Compiler
    ( compilerTests
    ) where

import           Data.ByteString                     (ByteString)
import           Data.Functor                        (void)
import           Data.Serialize                      (encode)
import           Data.Text                           (Text)
import           Haskoin.Crypto                      (ripemd160)
import           Haskoin.Script                      (Script (..),
                                                      ScriptOp (..), opPushData)
import           Haskoin.Util.Arbitrary.Keys         (arbitraryKeyPair)
import           Haskoin.Util.Arbitrary.Util         (arbitraryBSn)
import           Test.Tasty                          (TestTree, testGroup)
import           Test.Tasty.QuickCheck               (Gen, Property, Testable,
                                                      forAll, property, (===))

import           Language.Bitcoin.Miniscript         (Miniscript (..), compile,
                                                      let_)
import           Language.Bitcoin.Script.Descriptors (KeyDescriptor, keyBytes,
                                                      pubKey)
import           Language.Bitcoin.Script.Utils       (pushNumber)
import           Test.Example                        (Example (..),
                                                      testExampleProperty)
import qualified Test.Miniscript.Examples            as E
import           Test.Utils                          (forAllLabeled, pr12, pr3)


compilerTests :: TestTree
compilerTests = testGroup "compiler" examples
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


arbitraryKey :: Gen KeyDescriptor
arbitraryKey = pubKey . snd <$> arbitraryKeyPair


keyB :: Text -> KeyDescriptor -> (Text, Miniscript, ByteString)
keyB n k = (n, KeyDesc k, bs)
    where
    Just bs = keyBytes k


pushHash :: ByteString -> ScriptOp
pushHash = opPushData . encode . ripemd160


forKeys :: Testable p => [Text] -> ([(Text, Miniscript, ByteString)] -> p) -> Property
forKeys = forAllLabeled arbitraryKey keyB


arbitraryBytes32 :: Gen ByteString
arbitraryBytes32 = arbitraryBSn 32


scriptCompiles :: Example Miniscript -> [(Text, Miniscript)] -> Property
scriptCompiles e bs = void (compile . let_ bs $ script e) === Right ()


scriptCompilesTo :: Example Miniscript -> [(Text, Miniscript)] -> Script -> Property
scriptCompilesTo e bs s = compile (let_ bs $ script e) === Right s


example1 :: TestTree
example1 = testExampleProperty E.example1 $
    forAll arbitraryKey $ \k ->
    let Just bs = keyBytes k in
    scriptCompilesTo E.example1 [("key_1", KeyDesc k)] $ Script [opPushData bs, OP_CHECKSIG]


example2 :: TestTree
example2 = testExampleProperty E.example2 . forKeys ["key_1", "key_2"] $ \ks ->
    scriptCompilesTo E.example2 (pr12 <$> ks) $ result (pr3 <$> ks)
    where
    result [k1, k2] = Script [opPushData k1, OP_CHECKSIG, OP_SWAP, opPushData k2, OP_CHECKSIG, OP_BOOLOR]


example3 :: TestTree
example3 = testExampleProperty E.example3 . forKeys ["key_likely", "key_unlikely"] $ \ks ->
    scriptCompilesTo E.example3 (pr12 <$> ks) $ result (pr3 <$> ks)
    where
    result [k1, k2] = Script [ opPushData k1
                             , OP_CHECKSIG
                             , OP_IFDUP
                             , OP_NOTIF
                             , OP_DUP
                             , OP_HASH160
                             , pushHash k2
                             , OP_EQUALVERIFY
                             , OP_CHECKSIG
                             , OP_ENDIF
                             ]


example4 :: TestTree
example4 = testExampleProperty E.example4 . forKeys ["key_user", "key_service"] $ \ks ->
    scriptCompilesTo E.example4 (pr12 <$> ks) $ result (pr3 <$> ks)
    where
    result [k1, k2] = Script [ opPushData k1
                             , OP_CHECKSIGVERIFY
                             , opPushData k2
                             , OP_CHECKSIG
                             , OP_IFDUP
                             , OP_NOTIF
                             , pushNumber 12960
                             , OP_CHECKSEQUENCEVERIFY
                             , OP_ENDIF
                             ]


example5 :: TestTree
example5 = testExampleProperty E.example5 . forKeys ["key_1", "key_2", "key_3"] $ \ks ->
    scriptCompilesTo E.example5 (pr12 <$> ks) $ result (pr3 <$> ks)
    where
    result [k1, k2, k3] = Script [ opPushData k1
                                 , OP_CHECKSIG
                                 , OP_SWAP
                                 , opPushData k2
                                 , OP_CHECKSIG
                                 , OP_ADD
                                 , OP_SWAP
                                 , opPushData k3
                                 , OP_CHECKSIG
                                 , OP_ADD
                                 , OP_SWAP
                                 , OP_DUP
                                 , OP_IF
                                 , pushNumber 12960
                                 , OP_CHECKSEQUENCEVERIFY
                                 , OP_VERIFY
                                 , OP_ENDIF
                                 , OP_ADD
                                 , pushNumber 3
                                 , OP_EQUAL
                                 ]


example6 :: TestTree
example6 = testExampleProperty E.example6 . forKeys ["key_local", "key_revocation"] $ \ks ->
    scriptCompilesTo E.example6 (pr12 <$> ks) $ result (pr3 <$> ks)
    where
    result [k1, k2] = Script [ opPushData k1
                             , OP_CHECKSIG
                             , OP_NOTIF
                             , opPushData k2
                             , OP_CHECKSIG
                             , OP_ELSE
                             , pushNumber 1008
                             , OP_CHECKSEQUENCEVERIFY
                             , OP_ENDIF
                             ]


example7 :: TestTree
example7 = testExampleProperty E.example7 . forKeys ["key_local", "key_revocation", "key_remote"] $ \ks ->
    forAll arbitraryBytes32 $ \h ->
    let bindings = ("H", Bytes h) : (pr12 <$> ks)
        values   = h : (pr3 <$> ks)
    in scriptCompilesTo E.example7 bindings $ result values
    where
    result [h, k1, k2, k3] = Script [ opPushData k2
                                    , OP_CHECKSIG
                                    , OP_NOTIF
                                    , opPushData k3
                                    , OP_CHECKSIGVERIFY
                                    , opPushData k1
                                    , OP_CHECKSIG
                                    , OP_NOTIF
                                    , OP_SIZE
                                    , pushNumber 32
                                    , OP_EQUALVERIFY
                                    , OP_HASH160
                                    , opPushData h
                                    , OP_EQUALVERIFY
                                    , OP_ENDIF
                                    , OP_ENDIF
                                    , OP_1
                                    ]


example8 :: TestTree
example8 = testExampleProperty E.example8  . forKeys ["key_revocation", "key_remote", "key_local"] $ \ks ->
    forAll arbitraryBytes32 $ \h ->
    let bindings = ("H", Bytes h) : (pr12 <$> ks)
        values   = h : (pr3 <$> ks)
    in scriptCompilesTo E.example8 bindings $ result values
    where
    result [h, k1, k2, k3] = Script [ opPushData k2
                                    , OP_CHECKSIG
                                    , OP_NOTIF
                                    , opPushData k1
                                    , OP_CHECKSIG
                                    , OP_ELSE
                                    , OP_IF
                                    , OP_DUP
                                    , OP_HASH160
                                    , pushHash k3
                                    , OP_EQUALVERIFY
                                    , OP_CHECKSIGVERIFY
                                    , OP_SIZE
                                    , pushNumber 32
                                    , OP_EQUALVERIFY
                                    , OP_HASH160
                                    , opPushData h
                                    , OP_EQUAL
                                    , OP_ELSE
                                    , pushNumber 1008
                                    , OP_CHECKSEQUENCEVERIFY
                                    , OP_ENDIF
                                    , OP_ENDIF
                                    ]


example9 :: TestTree
example9 = testExampleProperty E.example9 . property $ scriptCompiles E.example9 mempty


example10 :: TestTree
example10 = testExampleProperty E.example10 $
    forKeys ["A", "B", "C", "D", "E"] $ \ks ->
    forKeys ["F", "G", "H"] $ \khs ->
    scriptCompilesTo E.example10 (fmap pr12 $ ks <> khs) $ result (fmap pr3 $ ks <> khs)
    where
    result [kA, kB, kC, kD, kE, kF, kG, kH]
        = Script [ pushNumber 4
                 , opPushData kA
                 , opPushData kB
                 , opPushData kC
                 , opPushData kD
                 , opPushData kE
                 , pushNumber 5
                 , OP_CHECKMULTISIG
                 , OP_IFDUP
                 , OP_NOTIF
                 , OP_DUP
                 , OP_HASH160
                 , pushHash kF
                 , OP_EQUALVERIFY
                 , OP_CHECKSIG
                 , OP_TOALTSTACK
                 , OP_DUP
                 , OP_HASH160
                 , pushHash kG
                 , OP_EQUALVERIFY
                 , OP_CHECKSIG
                 , OP_FROMALTSTACK
                 , OP_ADD
                 , OP_TOALTSTACK
                 , OP_DUP
                 , OP_HASH160
                 , pushHash kH
                 , OP_EQUALVERIFY
                 , OP_CHECKSIG
                 , OP_FROMALTSTACK
                 , OP_ADD
                 , pushNumber 2
                 , OP_EQUALVERIFY
                 , pushNumber 13149
                 , OP_CHECKSEQUENCEVERIFY
                 , OP_ENDIF
                 ]
