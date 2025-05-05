module Test.Crypto.Age.Identity.Gen
  ( genScryptIdentity
  , genX25519Identity
  , genIdentity
  ) where

import Crypto.Age.Identity
  ( Identity (..)
  , ScryptIdentity (..)
  , X25519Identity (..)
  , bytesToX25519Identity
  )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Crypto.Age.Scrypt.Gen ( genPassphrase, genWorkFactor )
import Test.Gen ( genByteArray )

genScryptIdentity :: Gen ScryptIdentity
genScryptIdentity =
  ScryptIdentity
    <$> genPassphrase
    <*> genWorkFactor

genX25519Identity :: Gen X25519Identity
genX25519Identity = do
  bs <- genByteArray (Range.singleton 32)
  case bytesToX25519Identity bs of
    Nothing -> fail "failed to generate a X25519Identity"
    Just x -> pure x

genIdentity :: Gen Identity
genIdentity =
  Gen.choice
    [ IdentityScrypt <$> genScryptIdentity
    , IdentityX25519 <$> genX25519Identity
    ]
