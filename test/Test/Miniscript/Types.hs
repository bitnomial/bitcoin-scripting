{-# LANGUAGE OverloadedStrings #-}

module Test.Miniscript.Types (
    typeCheckerTests,
) where

import Haskoin.Util.Arbitrary (arbitraryBSn, arbitraryKeyPair)
import Language.Bitcoin.Miniscript (
    BaseType (..),
    Miniscript (..),
    MiniscriptType (..),
    let_,
    typeCheckMiniscript,
 )
import Language.Bitcoin.Script.Descriptors (KeyDescriptor, pubKey)
import Test.Example (script)
import Test.Miniscript.Examples (
    example6,
    example7,
    example8,
 )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (
    Gen,
    forAll,
    testProperty,
    (===),
 )
import Test.Utils (globalContext)



typeCheckerTests :: TestTree
typeCheckerTests = testGroup "type checker" [localPolicy, offeredPolicy, receivedPolicy]


arbitraryKey :: Gen KeyDescriptor
arbitraryKey = pubKey . snd <$> arbitraryKeyPair globalContext



localPolicy :: TestTree
localPolicy = testProperty "bolt3 local policy" $
    forAll arbitraryKey $ \local ->
        forAll arbitraryKey $ \rev ->
            (baseType <$> typeCheckMiniscript mempty (bolt3LocalPolicy local rev)) === Right TypeB
  where
    bolt3LocalPolicy loc rev =
        let_
            [ ("key_local", KeyDesc loc)
            , ("key_revocation", KeyDesc rev)
            ]
            $ script example6


offeredPolicy :: TestTree
offeredPolicy = testProperty "bolt 3 offered policy" $
    forAll arbitraryKey $ \remote ->
        forAll arbitraryKey $ \local ->
            forAll arbitraryKey $ \revokation ->
                forAll (arbitraryBSn 32) $ \h ->
                    (baseType <$> typeCheckMiniscript mempty (bolt3OfferedHTLCPolicy remote local revokation h)) === Right TypeB
  where
    bolt3OfferedHTLCPolicy rmt loc rev h =
        let_
            [ ("key_remote", KeyDesc rmt)
            , ("key_local", KeyDesc loc)
            , ("key_revocation", KeyDesc rev)
            , ("H", Bytes h)
            ]
            $ script example7


receivedPolicy :: TestTree
receivedPolicy = testProperty "bolt 3 received policy" $
    forAll arbitraryKey $ \remote ->
        forAll arbitraryKey $ \local ->
            forAll arbitraryKey $ \revokation ->
                forAll (arbitraryBSn 32) $ \h ->
                    (baseType <$> typeCheckMiniscript mempty (bolt3ReceivedHTLCPolicy remote local revokation h)) === Right TypeB
  where
    bolt3ReceivedHTLCPolicy rmt loc rev h =
        let_
            [ ("key_remote", KeyDesc rmt)
            , ("key_local", KeyDesc loc)
            , ("key_revocation", KeyDesc rev)
            , ("H", Bytes h)
            ]
            $ script example8
