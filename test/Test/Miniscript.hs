{-# LANGUAGE OverloadedStrings #-}

-- |
--  Module: Test.Miniscript
--
--  Examples taken from <http://bitcoin.sipa.be/miniscript/>
module Test.Miniscript (
    miniscriptTests,
) where

import Haskoin.Network (btc)
import Language.Bitcoin.Miniscript (miniscriptToText, parseMiniscript)
import Test.Example (testTextRep)
import Test.Miniscript.Compiler (compilerTests)
import Test.Miniscript.Examples
import Test.Miniscript.Types (typeCheckerTests)
import Test.Miniscript.Witness (witnessTests)
import Test.Tasty (TestTree, testGroup)



miniscriptTests :: TestTree
miniscriptTests =
    testGroup
        "miniscript"
        [ parsePrintTests
        , typeCheckerTests
        , compilerTests
        , witnessTests
        ]


parsePrintTests :: TestTree
parsePrintTests =
    testGroup "parsing-printing" $
        testTextRep (parseMiniscript btc) (miniscriptToText btc) <$> examples
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
