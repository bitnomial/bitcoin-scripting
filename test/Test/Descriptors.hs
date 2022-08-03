{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

-- | We took these examples from <https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md>
module Test.Descriptors (
    descriptorTests,
) where

import Data.Text (Text)
import Haskoin.Constants (btc)
import Haskoin.Keys (
    DerivPathI (..),
    PubKeyI (..),
    importPubKey,
    xPubImport,
 )
import Haskoin.Util (decodeHex)
import Test.Tasty (TestTree, testGroup)

import Language.Bitcoin.Script.Descriptors (
    ChecksumDescriptor (..),
    ChecksumStatus (..),
    Key (..),
    KeyCollection (..),
    KeyDescriptor (..),
    Origin (..),
    OutputDescriptor (..),
    ScriptDescriptor (..),
    descriptorToText,
    descriptorToTextWithChecksum,
    parseChecksumDescriptor,
    parseDescriptor,
 )
import Test.Descriptors.Utils (testDescriptorUtils)
import Test.Example (Example (..), testTextRep)

descriptorTests :: TestTree
descriptorTests =
    testGroup
        "descriptor tests"
        [ testGroup "without checksum" $
            (testTextRep (parseDescriptor btc) (descriptorToText btc) <$> examples)
                <> [testDescriptorUtils]
        , testGroup "with checksum" $
            ( testTextRep
                (parseChecksumDescriptor btc)
                (descriptorToTextWithChecksum btc . descriptor)
                <$> checksumExamples
            )
                <> [testDescriptorUtils]
        ]
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
        , example11
        , example12
        , example13
        , example14
        , example15
        , example16
        ]
    checksumExamples =
        zipWith
            withValidChecksum
            examples
            [ "gn28ywm7"
            , "8fhd9pwu"
            , "8zl0zxma"
            , "qkrrc7je"
            , "lq9sf04s"
            , "2wtr0ej5"
            , "hzhjw406"
            , "y9zthqta"
            , "qwx6n9lh"
            , "en3tu306"
            , "ks05yr6p"
            , "axav5m0j"
            , "h69t6zk4"
            , "ml40v0wf"
            , "t2zpj2eu"
            , "v66cvalc"
            ]

key :: PubKeyI -> KeyDescriptor
key = KeyDescriptor Nothing . Pubkey

hexPubkey :: Text -> PubKeyI
hexPubkey h = PubKeyI k True
  where
    Just k = importPubKey =<< decodeHex h

withValidChecksum ::
    Example OutputDescriptor -> Text -> Example ChecksumDescriptor
withValidChecksum example checksum =
    example
        { script =
            ChecksumDescriptor
                { descriptor = script example
                , checksumStatus = Valid
                , expectedChecksum = checksum
                }
        , text = text example <> "#" <> checksum
        }

example1 :: Example OutputDescriptor
example1 =
    Example
        { name = "pk"
        , text = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
        , script = ScriptPubKey . Pk $ key k
        }
  where
    k = hexPubkey "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

example2 :: Example OutputDescriptor
example2 =
    Example
        { name = "pkh"
        , text = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
        , script = ScriptPubKey . Pkh $ key k
        }
  where
    k = hexPubkey "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

example3 :: Example OutputDescriptor
example3 =
    Example
        { name = "wpkh"
        , text = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
        , script = P2WPKH $ key k
        }
  where
    k = hexPubkey "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

example4 :: Example OutputDescriptor
example4 =
    Example
        { name = "p2sh-p2wpkh"
        , text = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))"
        , script = WrappedWPkh $ key k
        }
  where
    k = hexPubkey "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"

example5 :: Example OutputDescriptor
example5 =
    Example
        { name = "combo"
        , text = "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
        , script = Combo $ key k
        }
  where
    k = hexPubkey "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

example6 :: Example OutputDescriptor
example6 =
    Example
        { name = "p2sh-p2wsh-p2pkh"
        , text = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"
        , script = WrappedWSh . Pkh $ key k
        }
  where
    k = hexPubkey "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"

example7 :: Example OutputDescriptor
example7 =
    Example
        { name = "multi"
        , text =
            "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,\
            \025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)"
        , script = ScriptPubKey $ Multi 1 [key k1, key k2]
        }
  where
    k1 = hexPubkey "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
    k2 = hexPubkey "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"

example8 :: Example OutputDescriptor
example8 =
    Example
        { name = "p2sh-multisig"
        , text =
            "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,\
            \03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))"
        , script = P2SH $ Multi 2 [key k1, key k2]
        }
  where
    k1 = hexPubkey "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"
    k2 = hexPubkey "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe"

example9 :: Example OutputDescriptor
example9 =
    Example
        { name = "p2sh-multisig lexicographic"
        , text =
            "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,\
            \022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))"
        , script = P2SH $ SortedMulti 2 [key k1, key k2]
        }
  where
    k1 = hexPubkey "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe"
    k2 = hexPubkey "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"

example10 :: Example OutputDescriptor
example10 =
    Example
        { name = "p2wsh-multi"
        , text =
            "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,\
            \03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,\
            \03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))"
        , script = P2WSH $ Multi 2 [key k1, key k2, key k3]
        }
  where
    k1 = hexPubkey "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
    k2 = hexPubkey "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb"
    k3 = hexPubkey "03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"

example11 :: Example OutputDescriptor
example11 =
    Example
        { name = "p2sh-p2wsh-mulisig"
        , text =
            "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,\
            \03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,\
            \02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))"
        , script = WrappedWSh $ Multi 1 [key k1, key k2, key k3]
        }
  where
    k1 = hexPubkey "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8"
    k2 = hexPubkey "03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4"
    k3 = hexPubkey "02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e"

example12 :: Example OutputDescriptor
example12 =
    Example
        { name = "xpub"
        , text = "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8)"
        , script = ScriptPubKey . Pk $ KeyDescriptor Nothing (XPub xpub Deriv Single)
        }
  where
    Just xpub = xPubImport btc "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

example13 :: Example OutputDescriptor
example13 =
    Example
        { name = "p2pkh-xpub with derivation"
        , text = "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1'/2)"
        , script = ScriptPubKey . Pkh $ KeyDescriptor Nothing (XPub xpub (Deriv :| 1 :/ 2) Single)
        }
  where
    Just xpub = xPubImport btc "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

example14 :: Example OutputDescriptor
example14 =
    Example
        { name = "pkh-xpub with origin and collection spec"
        , text = "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)"
        , script = ScriptPubKey . Pkh $ KeyDescriptor (Just (Origin fp (Deriv :| 44 :| 0 :| 0))) (XPub xpub (Deriv :/ 1) SoftKeys)
        }
  where
    Just xpub = xPubImport btc "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    fp = "d34db33f"

example15 :: Example OutputDescriptor
example15 =
    Example
        { name = "wsh-multisig xpub collections"
        , text =
            "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,\
            \xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
        , script =
            P2WSH $
                Multi
                    1
                    [ KeyDescriptor Nothing (XPub xpub1 (Deriv :/ 1 :/ 0) SoftKeys)
                    , KeyDescriptor Nothing (XPub xpub2 (Deriv :/ 0 :/ 0) SoftKeys)
                    ]
        }
  where
    Just xpub1 = xPubImport btc "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
    Just xpub2 = xPubImport btc "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

example16 :: Example OutputDescriptor
example16 =
    Example
        { name = "wsh-multi sorted"
        , text =
            "wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,\
            \xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
        , script =
            P2WSH $
                SortedMulti
                    1
                    [ KeyDescriptor Nothing (XPub xpub1 (Deriv :/ 1 :/ 0) SoftKeys)
                    , KeyDescriptor Nothing (XPub xpub2 (Deriv :/ 0 :/ 0) SoftKeys)
                    ]
        }
  where
    Just xpub1 = xPubImport btc "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
    Just xpub2 = xPubImport btc "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
