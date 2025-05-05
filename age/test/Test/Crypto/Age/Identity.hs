{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Age.Identity
  ( tests
  ) where

import Crypto.Age.Identity
  ( X25519Identity
  , bytesToX25519Identity
  , decodeX25519Identity
  , encodeX25519Identity
  , x25519IdentityToBytes
  )
import qualified Data.ByteArray as BA
import Data.Text ( Text )
import qualified Data.Text.Encoding as TE
import Hedgehog
  ( Property, checkParallel, discover, forAll, property, tripping )
import Prelude
import Test.Crypto.Age.Identity.Gen ( genX25519Identity )
import Test.Golden ( goldenTestWithEncoderAndDecoder )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'bytesToX25519Identity' and 'x25519IdentityToBytes' round trip.
prop_roundTrip_x25519IdentityBytes :: Property
prop_roundTrip_x25519IdentityBytes = property $ do
  identity <- forAll genX25519Identity
  tripping
    identity
    x25519IdentityToBytes
    bytesToX25519Identity

-- | Test that 'encodeX25519Identity' and 'decodeX25519Identity' round trip.
prop_roundTrip_encodeDecodeX25519Identity :: Property
prop_roundTrip_encodeDecodeX25519Identity = property $ do
  identity <- forAll genX25519Identity
  tripping
    identity
    unsafeEncodeX25519Identity
    decodeX25519Identity

prop_golden_x25519Identity_bytes :: Property
prop_golden_x25519Identity_bytes =
  goldenTestWithEncoderAndDecoder
    (BA.convert . x25519IdentityToBytes)
    (bytesToX25519Identity . BA.convert)
    goldenX25519Identity
    "test/golden/binary/x25519-identity/golden.bin"

prop_golden_x25519Identity_bech32 :: Property
prop_golden_x25519Identity_bech32 =
  goldenTestWithEncoderAndDecoder
    (TE.encodeUtf8 . unsafeEncodeX25519Identity)
    (decodeX25519Identity . TE.decodeUtf8)
    goldenX25519Identity
    "test/golden/bech32/x25519-identity/golden.txt"

------------------------------------------------------------------------------
-- Golden examples
------------------------------------------------------------------------------

goldenX25519Identity :: X25519Identity
goldenX25519Identity =
  case bytesToX25519Identity (BA.replicate 32 0x41) of
    Nothing -> error "goldenX25519Identity: impossible: could not construct X25519Identity"
    Just x -> x

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

unsafeEncodeX25519Identity :: X25519Identity -> Text
unsafeEncodeX25519Identity i =
  case encodeX25519Identity i of
    Left err -> error $ "unsafeEncodeX25519Identity: impossible: error encoding X25519Identity: " <> show err
    Right t -> t
