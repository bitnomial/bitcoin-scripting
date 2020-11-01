{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Compile miniscript into bitcoin script
module Language.Bitcoin.Miniscript.Compiler (
    CompilerError (..),
    compile,
    compileOnly,
) where

import Control.Exception (Exception)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (Except, runExcept, throwE)
import Control.Monad.Trans.Reader (
    ReaderT,
    local,
    runReaderT,
 )
import Data.Bifunctor (first)
import Data.Functor (void)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Serialize (encode)
import Data.Text (Text)
import Haskoin.Crypto (ripemd160)
import Haskoin.Script (
    Script (..),
    ScriptOp (..),
    opPushData,
 )

import Language.Bitcoin.Miniscript.Syntax (
    Miniscript (..),
    Value (..),
 )
import Language.Bitcoin.Miniscript.Types (
    MiniscriptTypeError (..),
    typeCheckMiniscript,
 )
import Language.Bitcoin.Script.Descriptors (KeyDescriptor, keyBytes)
import Language.Bitcoin.Script.Utils (pushNumber)
import Language.Bitcoin.Utils (requiredContextValue)

data CompilerError
    = FreeVariable Text
    | CompilerError Miniscript
    | TypeError MiniscriptTypeError
    | NotImplemented Miniscript
    | AbstractKey KeyDescriptor
    deriving (Eq, Show)

instance Exception CompilerError

-- | Type check and compile a miniscript
compile :: Miniscript -> Either CompilerError Script
compile script = do
    void . first TypeError $ typeCheckMiniscript mempty script
    compileOnly script

-- | Compile a miniscript without type checking
compileOnly :: Miniscript -> Either CompilerError Script
compileOnly = fmap Script . runExcept . (`runReaderT` Context mempty) . compileOpsInContext

newtype Context = Context {unContext :: Map Text (Context, Miniscript)}

addClosure :: Text -> Miniscript -> Context -> Context
addClosure n e c = Context . Map.insert n (c, e) $ unContext c

requiredScript :: Text -> ReaderT Context (Except CompilerError) (Context, Miniscript)
requiredScript name = requiredContextValue unContext (FreeVariable name) name

compileOpsInContext :: Miniscript -> ReaderT Context (Except CompilerError) [ScriptOp]
compileOpsInContext = \case
    Boolean x -> return $ if x then [OP_1] else [OP_0]
    Key vk -> getKeyScript vk
    KeyH vk -> do
        k <- getKeyBytes =<< requiredKey vk
        return [OP_DUP, OP_HASH160, opPushData (encode $ ripemd160 k), OP_EQUALVERIFY]
    Older vn -> do
        n <- requiredNumber vn
        return [pushNumber n, OP_CHECKSEQUENCEVERIFY]
    After vn -> do
        n <- requiredNumber vn
        return [pushNumber n, OP_CHECKLOCKTIMEVERIFY]
    Sha256 vb -> do
        b <- requiredBytes vb
        return $ sizeCheck <> [OP_SHA256, opPushData b, OP_EQUAL]
    Ripemd160 vb -> do
        b <- requiredBytes vb
        return $ sizeCheck <> [OP_RIPEMD160, opPushData b, OP_EQUAL]
    Hash256 vb -> do
        b <- requiredBytes vb
        return $ sizeCheck <> [OP_HASH256, opPushData b, OP_EQUAL]
    Hash160 vb -> do
        b <- requiredBytes vb
        return $ sizeCheck <> [OP_HASH160, opPushData b, OP_EQUAL]
    AndOr x y z -> do
        opsX <- compileOpsInContext x
        opsY <- compileOpsInContext y
        opsZ <- compileOpsInContext z
        return $ mconcat [opsX, pure OP_NOTIF, opsZ, pure OP_ELSE, opsY, pure OP_ENDIF]
    AndV x z -> do
        opsX <- compileOpsInContext x
        opsZ <- compileOpsInContext z
        return $ opsX <> opsZ
    AndB x z -> do
        opsX <- compileOpsInContext x
        opsZ <- compileOpsInContext z
        return $ opsX <> opsZ <> [OP_BOOLAND]
    OrB x z -> do
        opsX <- compileOpsInContext x
        opsZ <- compileOpsInContext z
        return $ opsX <> opsZ <> [OP_BOOLOR]
    OrC x z -> do
        opsX <- compileOpsInContext x
        opsZ <- compileOpsInContext z
        return $ mconcat [opsX, pure OP_NOTIF, opsZ, pure OP_ENDIF]
    OrD x z -> do
        opsX <- compileOpsInContext x
        opsZ <- compileOpsInContext z
        return $ mconcat [opsX, [OP_IFDUP, OP_NOTIF], opsZ, pure OP_ENDIF]
    OrI x z -> do
        opsX <- compileOpsInContext x
        opsZ <- compileOpsInContext z
        return $ mconcat [pure OP_IF, opsX, pure OP_ELSE, opsZ, pure OP_ENDIF]
    Thresh vk x xs -> do
        k <- requiredNumber vk
        opsX <- compileOpsInContext x
        opsXS <- traverse compileOpsInContext xs
        return . mconcat $ pure opsX <> concatMap addX opsXS <> [[pushNumber k, OP_EQUAL]]
      where
        addX ops = [ops, pure OP_ADD]
    Multi vk xs -> do
        k <- requiredNumber vk
        opsXS <- traverse getKeyScript xs
        return . mconcat $ pure [pushNumber k] <> opsXS <> pure [pushNumber (length xs), OP_CHECKMULTISIG]
    AnnA x -> annA <$> compileOpsInContext x
      where
        annA ops = OP_TOALTSTACK : ops <> [OP_FROMALTSTACK]
    AnnS x -> (OP_SWAP :) <$> compileOpsInContext x
    AnnC x -> (<> [OP_CHECKSIG]) <$> compileOpsInContext x
    AnnD x -> annD <$> compileOpsInContext x
      where
        annD ops = [OP_DUP, OP_IF] <> ops <> [OP_ENDIF]
    AnnV x -> annV <$> compileOpsInContext x
      where
        annV ops =
            let (ops', op) = unsnoc ops
             in case op of
                    OP_EQUAL -> ops' <> [OP_EQUALVERIFY]
                    OP_NUMEQUAL -> ops' <> [OP_NUMEQUALVERIFY]
                    OP_CHECKSIG -> ops' <> [OP_CHECKSIGVERIFY]
                    OP_CHECKMULTISIG -> ops' <> [OP_CHECKMULTISIGVERIFY]
                    _ -> ops <> [OP_VERIFY]
    AnnJ x -> annJ <$> compileOpsInContext x
      where
        annJ ops = [OP_SIZE, OP_0NOTEQUAL, OP_IF] <> ops <> [OP_ENDIF]
    AnnN x -> (<> [OP_0NOTEQUAL]) <$> compileOpsInContext x
    Var n -> do
        (c', s) <- requiredScript n
        local (const c') $ compileOpsInContext s
    Let n e b -> local (addClosure n e) $ compileOpsInContext b
    Number x -> return [pushNumber x]
    Bytes b -> return [opPushData b]
    KeyDesc k | Just b <- keyBytes k -> return [opPushData b]
    e@KeyDesc{} -> typeError e
  where
    sizeCheck = [OP_SIZE, pushNumber 32, OP_EQUALVERIFY]
    typeError = lift . throwE . TypeError . MiniscriptTypeError

    required f = \case
        Lit x -> return x
        Variable n -> requiredScript n >>= f . snd

    requiredNumber = required $ \case
        Number x -> return x
        e -> typeError e

    getKeyScript vk = fmap (pure . opPushData) $ requiredKey vk >>= getKeyBytes

    requiredKey = required $ \case
        KeyDesc k -> return k
        e -> typeError e

    getKeyBytes k
        | Just b <- keyBytes k = return b
        | otherwise = lift . throwE $ AbstractKey k

    requiredBytes = required $ \case
        Bytes b -> return b
        e -> typeError e

unsnoc :: [a] -> ([a], a)
unsnoc [] = error "unsnoc: empty list"
unsnoc [x] = ([], x)
unsnoc (x : xs) = let (zs, z) = unsnoc xs in (x : zs, z)
