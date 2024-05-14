module Test.Utils (
    forAllLabeled,
    pr12,
    pr23,
    pr3,
    globalContext,
) where

import Data.Text (Text)
import Haskoin.Crypto (Ctx, createContext)
import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty.QuickCheck (
    Gen,
    Property,
    Testable,
    forAll,
    property,
 )


pr12 :: (a, b, c) -> (a, b)
pr12 (x, y, _) = (x, y)


pr23 :: (a, b, c) -> (b, c)
pr23 (_, x, y) = (x, y)


pr3 :: (a, b, c) -> c
pr3 (_, _, x) = x


forAllLabeled ::
    (Testable p, Show a) =>
    Gen a ->
    (Text -> a -> b) ->
    [Text] ->
    ([b] -> p) ->
    Property
forAllLabeled g mkRow (l : ls) mkTest = forAll g $ \z -> forAllLabeled g mkRow ls $ mkTest . (mkRow l z :)
forAllLabeled _ _ _ mkTest = property $ mkTest []


-- | The global context is created once and never modified again, it is to be passed into cryptographic
-- functions and contains a number of large data structures that are generated at runtime. Impure functions like
-- `destroyContext` or `randomizeContext` must not be used against this global value
globalContext :: Ctx
globalContext = unsafePerformIO createContext
{-# NOINLINE globalContext #-}
