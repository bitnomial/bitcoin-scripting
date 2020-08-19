module Language.Bitcoin.Policy.Syntax where

import           Data.ByteString (ByteString)
import           Data.Text       (Text)

data Policy
    = Pk Text
    | After Int
    | Older Int
    | Sha256 ByteString
    | Hash256 ByteString
    | Ripemd160 ByteString
    | Hash160 ByteString
    | And Policy Policy
    | Or OrBranch OrBranch
    | Thresh Int [Policy]
    deriving (Eq, Ord, Show)


data OrBranch = OrBranch
    { branchWeight :: Maybe Int
    , branchPolicy :: Policy
    } deriving (Eq, Ord, Show)
