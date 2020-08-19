-- |

module Test.Miniscript.Types
    ( typeCheckerTests
    )  where

import           Haskoin.Util.Arbitrary.Keys           (arbitraryKeyPair)
import           Haskoin.Util.Arbitrary.Util           (arbitraryBSn)
import           Test.Tasty                            (TestTree, testGroup)
import           Test.Tasty.QuickCheck                 (Gen, forAll,
                                                        testProperty, (===))

import           Language.Bitcoin.Miniscript           (BaseType (..),
                                                        MiniscriptType (..),
                                                        typeCheckMiniscript)
import           Language.Bitcoin.Miniscript.Fragments (PolicyKey (..),
                                                        bolt3LocalPolicy,
                                                        bolt3OfferedHTLCPolicy,
                                                        bolt3ReceivedHTLCPolicy)
import           Language.Bitcoin.Script.Descriptors   (pubKey)


typeCheckerTests :: TestTree
typeCheckerTests = testGroup "type checker" [localPolicy, offeredPolicy, receivedPolicy]


arbitraryPolicyKey :: Gen (PolicyKey a)
arbitraryPolicyKey = PolicyKey . pubKey . snd <$> arbitraryKeyPair


localPolicy :: TestTree
localPolicy = testProperty "bolt3 local policy" $
    forAll arbitraryPolicyKey $ \local ->
    forAll arbitraryPolicyKey $ \rev ->
    (baseType <$> typeCheckMiniscript mempty (bolt3LocalPolicy local rev)) === Right TypeB


offeredPolicy :: TestTree
offeredPolicy = testProperty "bolt 3 offered policy" $
    forAll arbitraryPolicyKey $ \remote ->
    forAll arbitraryPolicyKey $ \local ->
    forAll arbitraryPolicyKey $ \revokation ->
    forAll (arbitraryBSn 32) $ \h ->
    (baseType <$> typeCheckMiniscript mempty (bolt3OfferedHTLCPolicy remote local revokation h)) === Right TypeB


receivedPolicy :: TestTree
receivedPolicy = testProperty "bolt 3 received policy" $
    forAll arbitraryPolicyKey $ \remote ->
    forAll arbitraryPolicyKey $ \local ->
    forAll arbitraryPolicyKey $ \revokation ->
    forAll (arbitraryBSn 32) $ \h ->
    (baseType <$> typeCheckMiniscript mempty (bolt3ReceivedHTLCPolicy remote local revokation h)) === Right TypeB
