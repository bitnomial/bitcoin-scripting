module Main (main) where

import Test.Tasty (defaultMain, testGroup)

import Test.Descriptors (descriptorTests)
import Test.Miniscript (miniscriptTests)


main :: IO ()
main = defaultMain $ testGroup "bitcoin scripting" [descriptorTests, miniscriptTests]
