{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Age.Recipient
  ( tests
  , goldenX25519Recipient
  ) where

import Crypto.Age.Recipient
  ( X25519Recipient
  , bytesToX25519Recipient
  , decodeX25519Recipient
  , encodeX25519Recipient
  , x25519RecipientToBytes
  )
import qualified Data.ByteArray as BA
import Data.Text ( Text )
import qualified Data.Text.Encoding as TE
import Hedgehog
  ( Property, checkParallel, discover, forAll, property, tripping )
import Prelude
import Test.Crypto.Age.Recipient.Gen ( genX25519Recipient )
import Test.Golden ( goldenTestWithEncoderAndDecoder )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'bytesToX25519Recipient' and 'x25519RecipientToBytes' round trip.
prop_roundTrip_x25519RecipientBytes :: Property
prop_roundTrip_x25519RecipientBytes = property $ do
  recipient <- forAll genX25519Recipient
  tripping
    recipient
    x25519RecipientToBytes
    bytesToX25519Recipient

-- | Test that 'encodeX25519Recipient' and 'decodeX25519Recipient' round trip.
prop_roundTrip_encodeDecodeX25519Recipient :: Property
prop_roundTrip_encodeDecodeX25519Recipient = property $ do
  recipient <- forAll genX25519Recipient
  tripping
    recipient
    unsafeEncodeX25519Recipient
    decodeX25519Recipient

prop_golden_x25519Recipient_bytes :: Property
prop_golden_x25519Recipient_bytes =
  goldenTestWithEncoderAndDecoder
    (BA.convert . x25519RecipientToBytes)
    (bytesToX25519Recipient . BA.convert)
    goldenX25519Recipient
    "test/golden/binary/x25519-recipient/golden.bin"

prop_golden_x25519Recipient_bech32 :: Property
prop_golden_x25519Recipient_bech32 =
  goldenTestWithEncoderAndDecoder
    (TE.encodeUtf8 . unsafeEncodeX25519Recipient)
    (decodeX25519Recipient . TE.decodeUtf8)
    goldenX25519Recipient
    "test/golden/bech32/x25519-recipient/golden.txt"

------------------------------------------------------------------------------
-- Golden examples
------------------------------------------------------------------------------

goldenX25519Recipient :: X25519Recipient
goldenX25519Recipient =
  case bytesToX25519Recipient (BA.replicate 32 0x41) of
    Nothing -> error "goldenX25519Recipient: impossible: could not construct X25519Recipient"
    Just x -> x

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

unsafeEncodeX25519Recipient :: X25519Recipient -> Text
unsafeEncodeX25519Recipient i =
  case encodeX25519Recipient i of
    Left err -> error $ "unsafeEncodeX25519Recipient: impossible: error encoding X25519Recipient: " <> show err
    Right t -> t
