{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Language.Bitcoin.Miniscript.Witness (
    satisfy,
    SatisfactionContext,
    satisfactionContext,
    signature,
    preimage,
    lookupSignature,
    lookupPreimage,
    ChainState (..),
    emptyChainState,
    Signature (..),
    SatisfactionError (..),
) where

import Control.Exception (Exception)
import Control.Monad.Trans.Reader (
    Reader,
    asks,
    local,
    runReader,
 )
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Either (rights)
import Data.Function (on)
import Data.List (foldl')
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (catMaybes, mapMaybe)
import Data.Serialize (encode)
import Data.Text (Text)
import Haskoin.Crypto (Sig)
import Haskoin.Keys (
    PubKeyI (..),
    exportPubKey,
 )
import Haskoin.Script (
    Script (..),
    ScriptOp (..),
    SigHash,
    TxSignature (..),
    encodeTxSig,
    opPushData,
 )

import Language.Bitcoin.Miniscript.Syntax (
    Miniscript (..),
    Value (..),
 )
import Language.Bitcoin.Script.Descriptors.Syntax (
    KeyDescriptor,
    keyDescPubKey,
 )

data Signature = Signature
    { sig :: !Sig
    , sigHash :: !SigHash
    }
    deriving (Eq, Show)

newtype OrdPubKeyI = OrdPubKeyI {unOrdPubKeyI :: PubKeyI}
    deriving (Eq, Show)

instance Ord OrdPubKeyI where
    compare = compare `on` toOrdered . unOrdPubKeyI
      where
        toOrdered (PubKeyI pk c) = exportPubKey c pk

data SatisfactionContext = SatisfactionContext
    { signatures :: Map OrdPubKeyI Signature
    , hashPreimages :: Map ByteString ByteString
    }
    deriving (Eq, Show)

instance Semigroup SatisfactionContext where
    icA <> icB =
        SatisfactionContext
            { signatures = signatures icA <> signatures icB
            , hashPreimages = hashPreimages icA <> hashPreimages icB
            }

instance Monoid SatisfactionContext where
    mempty = SatisfactionContext mempty mempty

-- | Use with the monoid instance to add a signature to the 'SatisfactionContext'
signature :: PubKeyI -> Signature -> SatisfactionContext
signature pk = (`SatisfactionContext` mempty) . Map.singleton (OrdPubKeyI pk)

-- | Use with the monoid instance to add preimage to the 'SatisfactionContext'
preimage ::
    -- | hash
    ByteString ->
    -- | preimage
    ByteString ->
    SatisfactionContext
preimage h = SatisfactionContext mempty . Map.singleton h

satisfactionContext :: [(ByteString, ByteString)] -> [(PubKeyI, Signature)] -> SatisfactionContext
satisfactionContext preimages sigs =
    SatisfactionContext
        { signatures = Map.fromList $ first OrdPubKeyI <$> sigs
        , hashPreimages = Map.fromList preimages
        }

lookupSignature :: PubKeyI -> SatisfactionContext -> Maybe Signature
lookupSignature pk = Map.lookup (OrdPubKeyI pk) . signatures

lookupPreimage :: ByteString -> SatisfactionContext -> Maybe ByteString
lookupPreimage h = Map.lookup h . hashPreimages

data ChainState = ChainState
    { blockHeight :: Maybe Int
    , utxoAge :: Maybe Int
    }
    deriving (Eq, Show)

emptyChainState :: ChainState
emptyChainState = ChainState Nothing Nothing

data SatisfactionError
    = MissingSignature [KeyDescriptor]
    | MissingPreimage ByteString
    | FreeVariable Text
    | TypeError Text Miniscript
    | Impossible
    | AbstractKey KeyDescriptor
    deriving (Eq, Show)

instance Exception SatisfactionError

data SatScript = SatScript
    { satWeight :: Int
    , satScript :: [ScriptOp]
    }
    deriving (Eq, Show)

instance Semigroup SatScript where
    SatScript n0 s0 <> SatScript n1 s1 = SatScript (n0 + n1) (s0 <> s1)

instance Monoid SatScript where
    mempty = SatScript 0 mempty

fromScript :: [ScriptOp] -> SatScript
fromScript s = SatScript (BS.length $ encode s) s

data SatResult = SatResult
    { sat :: Either SatisfactionError SatScript
    , dsat :: Either SatisfactionError SatScript
    }
    deriving (Eq, Show)

-- | Compute a scriptinput which satisfies this miniscript
satisfy :: ChainState -> SatisfactionContext -> Miniscript -> Either SatisfactionError Script
satisfy chainState sc = fmap (Script . satScript) . sat . (`runReader` mempty) . satisfy' chainState sc

satisfy' :: ChainState -> SatisfactionContext -> Miniscript -> Reader (Map Text Miniscript) SatResult
satisfy' chainState sc = \case
    Boolean False ->
        return
            SatResult
                { sat = Left Impossible
                , dsat = Right mempty
                }
    Boolean True ->
        return
            SatResult
                { sat = Right mempty
                , dsat = Left Impossible
                }
    Key vk -> withLiteral guardKey satisfyKey vk
      where
        satisfyKey k
            | Just pk <- keyDescPubKey k
              , Just s <- lookupSignature pk sc =
                satVals (fromScript [pushSig s]) (SatScript 1 [OP_0])
            | otherwise =
                return
                    SatResult
                        { sat = Left $ MissingSignature [k]
                        , dsat = return $ SatScript 1 [OP_0]
                        }
    KeyH vk -> withLiteral guardKey satisfyKeyH vk
      where
        satisfyKeyH k
            | Just pk <- keyDescPubKey k
              , Just s <- lookupSignature pk sc =
                satVals
                    (fromScript [pushSig s, pushKey pk])
                    (fromScript [OP_0, pushKey pk])
            | Just pk <- keyDescPubKey k =
                return
                    SatResult
                        { sat = Left $ MissingSignature [k]
                        , dsat = Right $ fromScript [OP_0, pushKey pk]
                        }
            | otherwise = satErr $ AbstractKey k
    Sha256 h -> withLiteral guardBytes satisfyHash h
    Ripemd160 h -> withLiteral guardBytes satisfyHash h
    Hash256 h -> withLiteral guardBytes satisfyHash h
    Hash160 h -> withLiteral guardBytes satisfyHash h
    AndOr x y z -> satAndOr <$> satisfyInContext x <*> satisfyInContext y <*> satisfyInContext z
      where
        satAndOr sx sy sz =
            SatResult
                { sat = satConcat sat sy sat sx `satOr` satConcat sat sz dsat sx
                , dsat = satConcat dsat sz dsat sx
                }
    AndV x y -> satAndV <$> satisfyInContext x <*> satisfyInContext y
      where
        satAndV sx sy =
            SatResult
                { sat = satConcat sat sy sat sx
                , dsat = return mempty
                }
    AndB x y -> satAndB <$> satisfyInContext x <*> satisfyInContext y
      where
        satAndB sx sy =
            SatResult
                { sat = satConcat sat sy sat sx
                , dsat = satConcat dsat sy dsat sx
                }
    OrB x z -> satOrB <$> satisfyInContext x <*> satisfyInContext z
      where
        satOrB sx sz =
            SatResult
                { sat = satConcat dsat sz sat sx `satOr` satConcat sat sz dsat sx
                , dsat = satConcat dsat sz dsat sx
                }
    OrC x z -> satOrC <$> satisfyInContext x <*> satisfyInContext z
      where
        satOrC sx sz =
            SatResult
                { sat = sat sx `satOr` satConcat sat sz dsat sx
                , dsat = Left Impossible
                }
    OrD x z -> satOrD <$> satisfyInContext x <*> satisfyInContext z
      where
        satOrD sx sz =
            SatResult
                { sat = sat sx `satOr` satConcat sat sz dsat sx
                , dsat = satConcat dsat sz dsat sx
                }
    OrI x z -> satOrI <$> satisfyInContext x <*> satisfyInContext z
      where
        satOrI sx sz =
            SatResult
                { sat =
                    let satA = (<> SatScript 1 [OP_1]) <$> sat sx
                        satB = (<> SatScript 1 [OP_0]) <$> sat sz
                     in satA `satOr` satB
                , dsat =
                    let dsatA = (<> SatScript 1 [OP_1]) <$> dsat sx
                        dsatB = (<> SatScript 1 [OP_0]) <$> dsat sz
                     in dsatA `satOr` dsatB
                }
    Thresh vk x xs -> withLiteral guardNumber satisfyThresh vk
      where
        satisfyThresh k = do
            sxs <- traverse satisfyInContext (x : xs)
            return
                SatResult
                    { sat = getSat $ satResults k sxs
                    , dsat = getSat $ dsatResults k sxs
                    }

        getSat = foldl' accumResult (Left Impossible)
        satResults k sxs = rights $ fmap mconcat . sequence <$> choose k sat dsat (reverse sxs)
        dsatResults k sxs = rights $ fmap mconcat . sequence <$> chooseComplement k sat dsat (reverse sxs)

        chooseComplement k f g zs = concatMap (\k' -> choose k' f g zs) $ filter (/= k) [0 .. length zs]

        accumResult z@(Right s0) s1
            | satWeight s1 < satWeight s0 = Right s1
            | otherwise = z
        accumResult Left{} s = Right s
    Multi vk vks -> withLiteral guardNumber stageSatisfyMulti vk
      where
        stageSatisfyMulti k = withKeys (satisfyMulti k) vks mempty

        satisfyMulti k ks
            | Just pks <- traverse keyDescPubKey ks
              , ss <- mapMaybe (`lookupSignature` sc) pks
              , Just result <- foldl' accumMS Nothing $ bestSigs k ss =
                satVals result (dsatScript k)
            | otherwise = return SatResult{sat = Left $ MissingSignature ks, dsat = return $ dsatScript k}

        bestSigs k ss = fromScript . (OP_0 :) . catMaybes <$> choose k (Just . pushSig) (const Nothing) ss

        accumMS Nothing s = Just s
        accumMS x@(Just s1) s2
            | satWeight s2 < satWeight s1 = Just s2
            | otherwise = x

        withKeys f (x : xs) ks = withLiteral guardKey (withKeys f xs . (: ks)) x
        withKeys f [] ks = f ks

        dsatScript k = SatScript (k + 1) $ replicate (k + 1) OP_0
    AnnA x -> satisfyInContext x
    AnnS x -> satisfyInContext x
    AnnC x -> satisfyInContext x
    AnnD x -> revise <$> satisfyInContext x
      where
        revise s =
            s
                { sat = (<> SatScript 1 [OP_1]) <$> sat s
                , dsat = return $ SatScript 1 [OP_0]
                }
    AnnV x -> revise <$> satisfyInContext x
      where
        revise s = s{dsat = Left Impossible}
    AnnJ x -> revise <$> satisfyInContext x
      where
        revise s = s{dsat = return $ SatScript 1 [OP_0]}
    AnnN x -> satisfyInContext x
    Number{} -> return SatResult{sat = return mempty, dsat = Left Impossible}
    Bytes{} -> return SatResult{sat = return mempty, dsat = Left Impossible}
    KeyDesc{} -> return SatResult{sat = return mempty, dsat = Left Impossible}
    Older va -> traverse onAge (utxoAge chainState) >>= maybe (satErr Impossible) return
      where
        onAge age = withLiteral guardNumber (return . satisfyOlder age) va
        satisfyOlder age reqAge
            | age >= reqAge = SatResult{sat = return mempty, dsat = Left Impossible}
            | otherwise = SatResult{sat = Left Impossible, dsat = return mempty}
    After vh -> traverse onHeight (blockHeight chainState) >>= maybe (satErr Impossible) return
      where
        onHeight h = withLiteral guardNumber (return . satisfyAfter h) vh
        satisfyAfter height reqHeight
            | height >= reqHeight = SatResult{sat = return mempty, dsat = Left Impossible}
            | otherwise = SatResult{sat = Left Impossible, dsat = return mempty}
    Var name -> requiredValue name satisfyInContext
    Let name x b -> local (Map.insert name x) $ satisfyInContext b
  where
    satisfyInContext = satisfy' chainState sc

    -- it is still possible to dissatisfy when we do not know the preimage since
    -- we can easily detect that some value is _not_ it
    satisfyHash h
        | Just p <- lookupPreimage h sc =
            satVals (fromScript [opPushData p]) (fromScript [opPushData $ otherValue p])
        | otherwise = satErr $ MissingPreimage h

pushSig :: Signature -> ScriptOp
pushSig (Signature s sh) = opPushData . encodeTxSig $ TxSignature s sh

pushKey :: PubKeyI -> ScriptOp
pushKey (PubKeyI k c) = opPushData $ exportPubKey c k

-- TODO fingerprinting implications
otherValue :: ByteString -> ByteString
otherValue bs
    | bs == zero32 = BS.pack $ replicate 32 0x1
    | otherwise = zero32

zero32 :: ByteString
zero32 = BS.pack $ replicate 32 0x0

withLiteral ::
    (Miniscript -> Either SatisfactionError a) ->
    (a -> Reader (Map Text Miniscript) SatResult) ->
    Value a ->
    Reader (Map Text Miniscript) SatResult
withLiteral g f = \case
    Lit n -> f n
    Variable n -> requiredValue n $ either satErr f . g

requiredValue ::
    Text ->
    (Miniscript -> Reader (Map Text Miniscript) SatResult) ->
    Reader (Map Text Miniscript) SatResult
requiredValue name f = asks (Map.lookup name) >>= maybe (satErr $ FreeVariable name) f

guardNumber :: Miniscript -> Either SatisfactionError Int
guardNumber (Number n) = return n
guardNumber e = Left $ TypeError "number" e

guardKey :: Miniscript -> Either SatisfactionError KeyDescriptor
guardKey (KeyDesc k) = return k
guardKey e = Left $ TypeError "key" e

guardBytes :: Miniscript -> Either SatisfactionError ByteString
guardBytes (Bytes b) = return b
guardBytes e = Left $ TypeError "bytes" e

satVals :: Monad m => SatScript -> SatScript -> m SatResult
satVals x y = return $ SatResult (Right x) (Right y)

satErr :: Monad m => SatisfactionError -> m SatResult
satErr = return . (SatResult <$> Left <*> Left)

satConcat :: (Applicative f, Monoid m) => (a -> f m) -> a -> (b -> f m) -> b -> f m
satConcat f x g y = (<>) <$> f x <*> g y

satOr :: Either e SatScript -> Either e SatScript -> Either e SatScript
satOr xA@(Right sA) xB@(Right sB)
    | satWeight sA <= satWeight sB = xA
    | otherwise = xB
satOr sA sB = sA <> sB

choose :: Int -> (a -> b) -> (a -> b) -> [a] -> [[b]]
choose 0 _ onExclude xs = [onExclude <$> xs]
choose k onInclude _ xs
    | k == length xs = [onInclude <$> xs]
    | k > length xs = []
choose k onInclude onExclude (x : xs) =
    (handleX onInclude <$> choose (k -1) onInclude onExclude xs)
        <> (handleX onExclude <$> choose k onInclude onExclude xs)
  where
    handleX f zs = f x : zs
choose _ _ _ [] = []
