{-# LANGUAGE DataKinds      #-}
{-# LANGUAGE KindSignatures #-}

module Language.Bitcoin.Miniscript.Fragments
    ( KeyRole (..)
    , PolicyKey (..)

      -- * BOLT 3
    , bolt3LocalPolicy
    , bolt3OfferedHTLCPolicy
    , bolt3ReceivedHTLCPolicy
    ) where

import           Data.ByteString                     (ByteString)

import           Language.Bitcoin.Miniscript.Syntax  (Annotation (..),
                                                      Miniscript (..),
                                                      Value (..), hash160, key,
                                                      keyH, (.:))
import           Language.Bitcoin.Script.Descriptors (KeyDescriptor)


-- | Tag to mark the role of a given key in the system
data KeyRole = Local | Remote | Revokation deriving (Eq, Show)


-- | Segregate keys by role at the type level
newtype PolicyKey (a :: KeyRole) = PolicyKey KeyDescriptor
    deriving (Eq, Show)


bolt3LocalPolicy
    :: PolicyKey 'Local
    -> PolicyKey 'Revokation
    -> Miniscript
bolt3LocalPolicy (PolicyKey local) (PolicyKey rev) = AndOr (key local) (Older (Lit 1008)) (key rev)


bolt3OfferedHTLCPolicy
    :: PolicyKey 'Remote
    -> PolicyKey 'Local
    -> PolicyKey 'Revokation
    -> ByteString
    -- ^ hash value (not preimage)
    -> Miniscript
bolt3OfferedHTLCPolicy (PolicyKey remote) (PolicyKey local) (PolicyKey rev) h
    = T .: OrC (key rev) (AndV (V .: key remote) (key local `OrC` (V .: hash160 h)))


bolt3ReceivedHTLCPolicy
    :: PolicyKey 'Remote
    -> PolicyKey 'Local
    -> PolicyKey 'Revokation
    -> ByteString
    -- ^ hash  value (not preimage)
    -> Miniscript
bolt3ReceivedHTLCPolicy (PolicyKey remote) (PolicyKey local) (PolicyKey rev) h
   = AndOr (key remote)
           (OrI (AndV (V .: keyH local) (hash160 h)) (Older (Lit 1008)))
           (key rev)
