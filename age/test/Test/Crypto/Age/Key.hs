{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Age.Key
  ( tests
  ) where

import Crypto.Age.Key
  ( FileKey (..)
  , PayloadKey (..)
  , bytesToFileKey
  , bytesToPayloadKey
  , bytesToPayloadKeyNonce
  , fileKeyToBytes
  , payloadKeyNonceToBytes
  , payloadKeyToBytes
  )
import qualified Data.ByteArray as BA
import Hedgehog
  ( Property, checkParallel, discover, forAll, forAllWith, property, tripping )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Crypto.Age.Key.Gen ( genFileKey, genPayloadKey, genPayloadKeyNonce )
import Test.Crypto.Age.Key.Render
  ( unsafeRenderFileKey, unsafeRenderPayloadKey )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'bytesToFileKey' only returns 'Just' when given 16 bytes.
prop_bytesToFileKey :: Property
prop_bytesToFileKey = property $ do
  bs <- forAll $ BA.convert <$> Gen.bytes (Range.constant 0 256)
  let bsLen = BA.length bs
  case bytesToFileKey bs of
    Nothing
      | bsLen == 16 -> fail "failed when given 16 bytes"
      | otherwise -> pure ()
    Just _
      | bsLen == 16 -> pure ()
      | otherwise -> fail $ "succeeded when given " <> show bsLen <> " bytes"

-- | Test that 'fileKeyToBytes' and 'bytesToFileKey' round trip.
prop_roundTrip_fileKeyBytes :: Property
prop_roundTrip_fileKeyBytes = property $ do
  fk <- forAllWith unsafeRenderFileKey genFileKey
  tripping
    (ShowableFileKey fk)
    (fileKeyToBytes . unShowableFileKey)
    ((ShowableFileKey <$>) . bytesToFileKey)

-- | Test that 'bytesToPayloadKeyNonce' only returns 'Just' when given 16 bytes.
prop_bytesToPayloadKeyNonce :: Property
prop_bytesToPayloadKeyNonce = property $ do
  bs <- forAll $ BA.convert <$> Gen.bytes (Range.constant 0 256)
  let bsLen = BA.length bs
  case bytesToPayloadKeyNonce bs of
    Nothing
      | bsLen == 16 -> fail "failed when given 16 bytes"
      | otherwise -> pure ()
    Just _
      | bsLen == 16 -> pure ()
      | otherwise -> fail $ "succeeded when given " <> show bsLen <> " bytes"

-- | Test that 'payloadKeyNonceToBytes' and 'bytesToPayloadKeyNonce' round
-- trip.
prop_roundTrip_payloadKeyNonceBytes :: Property
prop_roundTrip_payloadKeyNonceBytes = property $ do
  pkn <- forAll genPayloadKeyNonce
  tripping
    pkn
    payloadKeyNonceToBytes
    bytesToPayloadKeyNonce

-- | Test that 'bytesToPayloadKey' only returns 'Just' when given 32 bytes.
prop_bytesToPayloadKey :: Property
prop_bytesToPayloadKey = property $ do
  bs <- forAll $ BA.convert <$> Gen.bytes (Range.constant 0 256)
  let bsLen = BA.length bs
  case bytesToPayloadKey bs of
    Nothing
      | bsLen == 32 -> fail "failed when given 32 bytes"
      | otherwise -> pure ()
    Just _
      | bsLen == 32 -> pure ()
      | otherwise -> fail $ "succeeded when given " <> show bsLen <> " bytes"

-- | Test that 'payloadKeyToBytes' and 'bytesToPayloadKey' round
-- trip.
prop_roundTrip_payloadKeyBytes :: Property
prop_roundTrip_payloadKeyBytes = property $ do
  pk <- forAllWith unsafeRenderPayloadKey genPayloadKey
  tripping
    (ShowablePayloadKey pk)
    (payloadKeyToBytes . unShowablePayloadKey)
    ((ShowablePayloadKey <$>) . bytesToPayloadKey)

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

newtype ShowableFileKey = ShowableFileKey
  { unShowableFileKey :: FileKey }
  deriving newtype (Eq)

instance Show ShowableFileKey where
  show = unsafeRenderFileKey . unShowableFileKey

newtype ShowablePayloadKey = ShowablePayloadKey
  { unShowablePayloadKey :: PayloadKey }
  deriving newtype (Eq)

instance Show ShowablePayloadKey where
  show = unsafeRenderPayloadKey . unShowablePayloadKey
