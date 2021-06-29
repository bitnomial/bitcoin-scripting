{-# LANGUAGE OverloadedStrings #-}

module Test.Miniscript.Examples (
    example1,
    example2,
    example3,
    example4,
    example5,
    example6,
    example7,
    example8,
    example9,
    example10,
) where

import Data.Text (Text)
import Language.Bitcoin.Miniscript (
    Annotation (..),
    Miniscript (..),
    literal,
    older,
    thresh,
    var,
    (.:),
 )
import Test.Example (Example (..))

keyVar :: Text -> Miniscript
keyVar = AnnC . Key . var

keyHVar :: Text -> Miniscript
keyHVar = AnnC . KeyH . var

example1 :: Example Miniscript
example1 =
    Example
        { name = "A single key"
        , text = "pk(key_1)"
        , script = keyVar "key_1"
        }

example2 :: Example Miniscript
example2 =
    Example
        { name = "One of two keys (equally likely)"
        , text = "or_b(pk(key_1),s:pk(key_2))"
        , script = keyVar "key_1" `OrB` (S .: keyVar "key_2")
        }

example3 :: Example Miniscript
example3 =
    Example
        { name = "One of two keys (one likely, one unlikely)"
        , text = "or_d(pk(key_likely),pkh(key_unlikely))"
        , script = keyVar "key_likely" `OrD` keyHVar "key_unlikely"
        }

example4 :: Example Miniscript
example4 =
    Example
        { name = "A user and a 2FA service need to sign off, but after 90 days the user alone is enough"
        , text = "and_v(v:pk(key_user),or_d(pk(key_service),older(12960)))"
        , script = AndV (V .: keyVar "key_user") (keyVar "key_service" `OrD` older 12960)
        }

example5 :: Example Miniscript
example5 =
    Example
        { name = "A 3-of-3 that turns into a 2-of-3 after 90 days"
        , text = "thresh(3,pk(key_1),s:pk(key_2),s:pk(key_3),sdv:older(12960))"
        , script =
            thresh
                3
                (keyVar "key_1")
                [ S .: keyVar "key_2"
                , S .: keyVar "key_3"
                , [S, D, V] .: older 12960
                ]
        }

example6 :: Example Miniscript
example6 =
    Example
        { name = "The BOLT #3 to_local policy"
        , text = "andor(pk(key_local),older(1008),pk(key_revocation))"
        , script = AndOr (keyVar "key_local") (older 1008) (keyVar "key_revocation")
        }

example7 :: Example Miniscript
example7 =
    Example
        { name = "The BOLT #3 offered HTLC policy"
        , text = "t:or_c(pk(key_revocation),and_v(v:pk(key_remote),or_c(pk(key_local),v:hash160(H))))"
        , script =
            T
                .: ( keyVar "key_revocation"
                        `OrC` AndV
                            (V .: keyVar "key_remote")
                            (keyVar "key_local" `OrC` (V .: Hash160 (var "H")))
                   )
        }

example8 :: Example Miniscript
example8 =
    Example
        { name = "The BOLT #3 received HTLC policy"
        , text = "andor(pk(key_remote),or_i(and_v(v:pkh(key_local),hash160(H)),older(1008)),pk(key_revocation))"
        , script =
            AndOr
                (keyVar "key_remote")
                (AndV (V .: keyHVar "key_local") (Hash160 $ var "H") `OrI` older 1008)
                (keyVar "key_revocation")
        }

example9 :: Example Miniscript
example9 =
    Example
        { name = "Let binding"
        , text = "let timeout = 1008 in older(timeout)"
        , script = Let "timeout" (Number 1008) $ Older (var "timeout")
        }

-- ht @shesek
example10 :: Example Miniscript
example10 =
    Example
        { name = "Advanced 2FA"
        , text = "or_d(multi(4,A,B,C,D,E),and_v(v:thresh(2,pkh(F),a:pkh(G),a:pkh(H)),older(13149)))"
        , script = Multi (literal 4) [kA, kB, kC, kD, kE] `OrD` AndV (V .: thresh 2 kF [A .: kG, A .: kH]) (older 13149)
        }
  where
    kA = var "A"
    kB = var "B"
    kC = var "C"
    kD = var "D"
    kE = var "E"

    kF = keyHVar "F"
    kG = keyHVar "G"
    kH = keyHVar "H"
