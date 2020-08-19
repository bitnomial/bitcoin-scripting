-- |
-- Module: Language.Bitcoin.Miniscript
--
-- Haskell embedding of miniscript.  See http://bitcoin.sipa.be/miniscript/ for
-- details.  Much of the documentation below is taken from this site.
module Language.Bitcoin.Miniscript
    ( -- * Syntax tree
      Value (..)
    , var
    , literal
    , Miniscript (..)
    , let_
    , key
    , keyH
    , older
    , after
    , sha256
    , ripemd160
    , hash256
    , hash160
    , thresh
    , multi

    , MiniscriptAnnotation (..)
    , Annotation (..)

      -- * Type system
    , BaseType (..)
    , ModField (..)
    , MiniscriptType (..)
    , boolType
    , numberType
    , bytesType
    , keyDescriptorType
    , typeCheckMiniscript
    , MiniscriptTypeError (..)

      -- * Compilation
    , compile
    , compileOnly
    , CompilerError (..)

      -- * Printing and parsing
    , miniscriptToText
    , miniscriptParser
    , parseMiniscript
    ) where

import           Language.Bitcoin.Miniscript.Compiler
import           Language.Bitcoin.Miniscript.Parser
import           Language.Bitcoin.Miniscript.Syntax
import           Language.Bitcoin.Miniscript.Text
import           Language.Bitcoin.Miniscript.Types
