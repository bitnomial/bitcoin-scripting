{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Types and type checking
module Language.Bitcoin.Miniscript.Types (
    BaseType (..),
    ModField (..),
    MiniscriptType (..),
    boolType,
    numberType,
    bytesType,
    keyDescriptorType,
    typeCheckMiniscript,
    MiniscriptTypeError (..),
) where

import Control.Monad (unless)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (Except, runExcept, throwE)
import Control.Monad.Trans.Reader (ReaderT, local, runReaderT)
import Data.Bool (bool)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)

import Language.Bitcoin.Miniscript.Syntax (
    Miniscript (..),
    Value (..),
 )
import Language.Bitcoin.Utils (requiredContextValue)


{-# ANN module ("HLint: ignore Reduce duplication" :: String) #-}


data BaseType
    = -- | Base expression
      TypeB
    | -- | Verify expression
      TypeV
    | -- | Key expression
      TypeK
    | -- | Wrapped expression
      TypeW
    | -- | Number expression
      TypeNumber
    | -- | Bytes expression
      TypeBytes
    | -- | Key descriptor type
      TypeKeyDesc
    deriving (Eq, Show)


notW :: BaseType -> Bool
notW = (/= TypeW)


-- | Type modifications that imply additional properties of the expression
data ModField = ModField
    { modZ :: Bool
    -- ^ Consumes exactly 0 stack elements
    , modO :: Bool
    -- ^ One-arg: this expression always consumes exactly 1 stack element.
    , modN :: Bool
    -- ^ Nonzero: this expression always consumes at least 1 stack element, no
    -- satisfaction for this expression requires the top input stack element to
    -- be zero.
    , modD :: Bool
    -- ^ Dissatisfiable: a dissatisfaction for this expression can
    -- unconditionally be constructed.
    , modU :: Bool
    -- ^ Unit: when satisfied put exactly 1 on the stack
    }
    deriving (Eq, Show)


data MiniscriptType = MiniscriptType
    { baseType :: BaseType
    , modifiers :: ModField
    }
    deriving (Eq, Show)


emptyModField :: ModField
emptyModField = ModField False False False False False


boolType :: Bool -> MiniscriptType
boolType = MiniscriptType TypeB . bool falseMods trueMods
  where
    trueMods = emptyModField{modZ = True, modU = True}
    falseMods = emptyModField{modZ = True, modU = True, modD = True}


numberType :: MiniscriptType
numberType = MiniscriptType TypeNumber emptyModField


bytesType :: MiniscriptType
bytesType = MiniscriptType TypeBytes emptyModField


keyDescriptorType :: MiniscriptType
keyDescriptorType = MiniscriptType TypeKeyDesc emptyModField


data MiniscriptTypeError
    = MiniscriptTypeError Miniscript
    | UntypedVariable Text
    | -- | fields: @name expectedBaseType typeAnnotation@
      WrongVariableType Text BaseType MiniscriptType
    deriving (Eq, Show)


type TypeCheckM a = ReaderT (Map Text MiniscriptType) (Except MiniscriptTypeError) a


requiredVarType :: Text -> TypeCheckM MiniscriptType
requiredVarType name = requiredContextValue id (UntypedVariable name) name


-- | Check that a miniscript expression is well-typed.
typeCheckMiniscript ::
    -- | type hints for free variables in the miniscript expression
    Map Text MiniscriptType ->
    Miniscript ->
    Either MiniscriptTypeError MiniscriptType
typeCheckMiniscript context = runExcept . (`runReaderT` context) . typeCheckInContext


typeCheckInContext :: Miniscript -> TypeCheckM MiniscriptType
typeCheckInContext = \case
    Var name -> requiredVarType name
    Let name expr body -> do
        ty <- typeCheckInContext expr
        local (Map.insert name ty) $ typeCheckInContext body
    Boolean b -> return $ boolType b
    Number{} -> return numberType
    Bytes{} -> return bytesType
    KeyDesc{} -> return keyDescriptorType
    Key x -> ondu TypeK <$ literal TypeKeyDesc x
    KeyH x -> ndu TypeK <$ literal TypeKeyDesc x
    Older x -> literal TypeNumber x >> exprType TypeB emptyModField{modZ = True}
    After x -> literal TypeNumber x >> exprType TypeB emptyModField{modZ = True}
    Sha256 x -> ondu TypeB <$ literal TypeBytes x
    Ripemd160 x -> ondu TypeB <$ literal TypeBytes x
    Hash256 x -> ondu TypeB <$ literal TypeBytes x
    Hash160 x -> ondu TypeB <$ literal TypeBytes x
    e@(AndOr x y z) -> do
        tx <- typeCheckInContext x
        ty <- typeCheckInContext y
        tz <- typeCheckInContext z

        let mx = modifiers tx
            my = modifiers ty
            mz = modifiers tz

            bty = baseType ty

        if (baseType tx == TypeB) && (baseType tz == bty) && notW bty && modD mx && modU mx
            then
                exprType
                    bty
                    emptyModField
                        { modZ = modZ mx && modZ my && modZ mz
                        , modO = (modZ mx && modO my && modO mz) || (modO mx && modZ my && modZ mz)
                        , modU = modU my && modU mz
                        , modD = modD mz
                        }
            else typeError e
    e@(AndV x y) -> do
        tx <- typeCheckInContext x
        ty <- typeCheckInContext y
        let mx = modifiers tx
            my = modifiers ty
            bty = baseType ty
        if baseType tx == TypeV && notW bty
            then
                exprType
                    bty
                    emptyModField
                        { modZ = modZ mx && modZ my
                        , modO = (modZ mx && modO my) || (modO mx && modZ my)
                        , modN = modN mx || (modZ mx && modN my)
                        , modU = modU my
                        }
            else typeError e
    e@(AndB x y) -> do
        tx <- typeCheckInContext x
        ty <- typeCheckInContext y
        let mx = modifiers tx
            my = modifiers ty
        if baseType tx == TypeB && baseType ty == TypeW
            then
                exprType
                    TypeB
                    emptyModField
                        { modZ = modZ mx && modZ my
                        , modO = (modZ mx && modO my) || (modO mx && modZ my)
                        , modN = modN mx || (modZ mx && modN my)
                        , modD = modD mx && modD my
                        , modU = True
                        }
            else typeError e
    e@(OrB x z) -> do
        tx <- typeCheckInContext x
        tz <- typeCheckInContext z
        let mx = modifiers tx
            mz = modifiers tz
        if baseType tx == TypeB && baseType tz == TypeW && modD mx && modD mz
            then
                exprType
                    TypeB
                    emptyModField
                        { modZ = modZ mx && modZ mz
                        , modO =
                            (modZ mx && modO mz)
                                || (modO mx && modZ mz)
                        , modD = True
                        , modU = True
                        }
            else typeError e
    e@(OrC x z) -> do
        tx <- typeCheckInContext x
        tz <- typeCheckInContext z
        let mx = modifiers tx
            mz = modifiers tz
        if baseType tx == TypeB && baseType tz == TypeV && modD mx && modU mx
            then
                exprType
                    TypeV
                    emptyModField
                        { modZ = modZ mx && modZ mz
                        , modO = modO mx && modZ mz
                        }
            else typeError e
    e@(OrD x z) -> do
        tx <- typeCheckInContext x
        tz <- typeCheckInContext z
        let mx = modifiers tx
            mz = modifiers tz
        if baseType tx == TypeB && baseType tz == TypeB && modD mx && modU mx
            then
                exprType
                    TypeB
                    emptyModField
                        { modZ = modZ mx && modZ mz
                        , modO = modO mx && modZ mz
                        , modD = modD mz
                        , modU = modU mz
                        }
            else typeError e
    e@(OrI x z) -> do
        tx <- typeCheckInContext x
        tz <- typeCheckInContext z
        let mx = modifiers tx
            mz = modifiers tz
            btx = baseType tx
        if (baseType tz == btx) && notW btx
            then
                exprType
                    btx
                    emptyModField
                        { modO = modZ mx && modZ mz
                        , modD = modD mx || modD mz
                        , modU = modU mx && modU mz
                        }
            else typeError e
    e@(Thresh k x ys) -> do
        literal TypeNumber k
        tx <- typeCheckInContext x
        tys <- traverse typeCheckInContext ys
        let mx = modifiers tx
            mys = modifiers <$> tys
            allMods = mx : mys
            zCount = count modZ allMods
            oCount = count modO allMods :: Int
            count f = sum . fmap (bool 0 1 . f)
            isDU m = modD m && modU m

        if baseType tx == TypeB && all (== TypeW) (baseType <$> tys) && all isDU allMods
            then
                exprType
                    TypeB
                    emptyModField
                        { modZ = all modZ allMods
                        , modO = zCount == length ys && oCount == 1
                        , modD = True
                        , modU = True
                        }
            else typeError e
    Multi k ks -> do
        literal TypeNumber k
        mapM_ (literal TypeKeyDesc) ks
        return $ ndu TypeB
    e@(AnnA x) -> do
        tx <- typeCheckInContext x
        let mx = modifiers tx
        if baseType tx == TypeB
            then
                exprType
                    TypeW
                    emptyModField
                        { modD = modD mx
                        , modU = modU mx
                        }
            else typeError e
    e@(AnnS x) -> do
        tx <- typeCheckInContext x
        let mx = modifiers tx
        if baseType tx == TypeB && modO mx
            then
                exprType
                    TypeW
                    emptyModField
                        { modD = modD mx
                        , modU = modU mx
                        }
            else typeError e
    e@(AnnC x) -> do
        tx <- typeCheckInContext x
        let mx = modifiers tx
        if baseType tx == TypeK
            then
                exprType
                    TypeB
                    emptyModField
                        { modO = modO mx
                        , modN = modN mx
                        , modD = modD mx
                        , modU = True
                        }
            else typeError e
    e@(AnnD x) -> do
        tx <- typeCheckInContext x
        let mx = modifiers tx
        if baseType tx == TypeV && modZ mx
            then
                exprType
                    TypeB
                    emptyModField
                        { modO = modZ mx
                        , modN = True
                        , modU = True
                        , modD = True
                        }
            else typeError e
    e@(AnnV x) -> do
        tx <- typeCheckInContext x
        let mx = modifiers tx
        if baseType tx == TypeB
            then
                exprType
                    TypeV
                    emptyModField
                        { modZ = modZ mx
                        , modO = modO mx
                        , modN = modN mx
                        }
            else typeError e
    e@(AnnJ x) -> do
        tx <- typeCheckInContext x
        let mx = modifiers tx
        if baseType tx == TypeB && modN mx
            then
                exprType
                    TypeB
                    emptyModField
                        { modO = modO mx
                        , modN = True
                        , modD = True
                        , modU = modU mx
                        }
            else typeError e
    e@(AnnN x) -> do
        tx <- typeCheckInContext x
        let mx = modifiers tx
        if baseType tx == TypeB
            then
                exprType
                    TypeB
                    emptyModField
                        { modZ = modZ mx
                        , modO = modO mx
                        , modN = modN mx
                        , modD = modD mx
                        , modU = True
                        }
            else typeError e
  where
    ondu = flip MiniscriptType emptyModField{modO = True, modN = True, modD = True, modU = True}
    ndu = flip MiniscriptType emptyModField{modN = True, modD = True, modU = True}

    exprType t = return . MiniscriptType t
    typeError = lift . throwE . MiniscriptTypeError

    literal bt (Variable n) = do
        t' <- requiredVarType n
        unless (baseType t' == bt) . lift . throwE $ WrongVariableType n bt t'
    literal _ _ = return ()
