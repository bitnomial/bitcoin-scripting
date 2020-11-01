module Test.Example (
    Example (..),
    testTextRep,
    testExampleProperty,
) where

import Data.Text (Text)
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (assertFailure, testCase, (@=?))
import Test.Tasty.QuickCheck (Property, testProperty)

data Example a = Example
    { name :: String
    , text :: Text
    , script :: a
    }

testTextRep ::
    (Eq a, Show a) =>
    (Text -> Either String a) ->
    (a -> Text) ->
    Example a ->
    TestTree
testTextRep parse encode e =
    testCase (name e)
        . either assertFailure parseSuccess
        $ parse (text e)
  where
    parseSuccess d = do
        d @=? script e
        encode d @=? text e

testExampleProperty :: Example a -> Property -> TestTree
testExampleProperty e = testProperty (name e)
