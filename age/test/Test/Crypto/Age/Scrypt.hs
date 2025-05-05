{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Age.Scrypt
  ( tests
  , goldenWorkFactor
  ) where

import Crypto.Age.Scrypt
  ( WorkFactor
  , bytesToSalt
  , mkWorkFactor
  , saltToBytes
  , workFactorBuilder
  , workFactorParser
  )
import Data.Attoparsec.ByteString ( parseOnly )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.ByteString.Builder ( Builder, toLazyByteString )
import qualified Data.ByteString.Builder as Builder
import Data.Word ( Word8 )
import Hedgehog
  ( Property, checkParallel, discover, forAll, property, tripping )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Crypto.Age.Scrypt.Gen ( genSalt, genWorkFactorInRange )
import Test.Golden ( goldenTestWithEncoderAndDecoder )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'bytesToSalt' only returns 'Just' when given 16 bytes.
prop_bytesToSalt :: Property
prop_bytesToSalt = property $ do
  bs <- forAll $ Gen.bytes (Range.constant 0 256)
  let bsLen = BS.length bs
  case bytesToSalt bs of
    Nothing
      | bsLen == 16 -> fail "failed when given 16 bytes"
      | otherwise -> pure ()
    Just _
      | bsLen == 16 -> pure ()
      | otherwise -> fail $ "succeeded when given " <> show bsLen <> " bytes"

-- | Test that 'saltToBytes' and 'bytesToSalt' round trip.
prop_roundTrip_saltBytes :: Property
prop_roundTrip_saltBytes = property $ do
  salt <- forAll genSalt
  tripping
    salt
    saltToBytes
    bytesToSalt

-- | Test that 'mkWorkFactor' only returns 'Just' when given an integer
-- @0 < n <= 64@.
prop_mkWorkFactor :: Property
prop_mkWorkFactor = property $ do
  n <- forAll $ Gen.word8 Range.constantBounded
  case mkWorkFactor n of
    Nothing
      | isValid n -> fail $ "failed when given " <> show n
      | otherwise -> pure ()
    Just _
      | isValid n -> pure ()
      | otherwise -> fail $ "succeeded when given " <> show n
  where
    isValid :: Word8 -> Bool
    isValid w8
      | w8 >= 1 && w8 <= 64 = True
      | otherwise = False

-- | Test that 'workFactorBuilder' and 'workFactorParser' round trip.
prop_roundTrip_encodeParseWorkFactor :: Property
prop_roundTrip_encodeParseWorkFactor = property $ do
  workFactor <- forAll $ genWorkFactorInRange (Range.constant 1 64)
  tripping
    workFactor
    (toStrictByteString . workFactorBuilder)
    (parseOnly workFactorParser)

-- | Test that 'workFactorParser' fails when parsing a work factor with leading
-- zeroes.
prop_workFactorParser_failOnLeadingZeroes :: Property
prop_workFactorParser_failOnLeadingZeroes = property $ do
  workFactor <- forAll $ genWorkFactorInRange (Range.constant 1 64)
  let encodedWorkFactor = toStrictByteString (workFactorBuilder workFactor)
  leadingZeroes <- forAll $ Gen.utf8 (Range.constant 1 256) (pure '0')
  let encodedWorkFactorWithLeadingZeroes = leadingZeroes <> encodedWorkFactor
  case parseOnly workFactorParser encodedWorkFactorWithLeadingZeroes of
    Left _ -> pure ()
    Right _ -> fail $ "succeeded when parsing " <> show encodedWorkFactorWithLeadingZeroes

-- | Test that 'workFactorParser' fails when parsing a work factor that is @0@
-- or greater than @64@.
prop_workFactorParser_cannotParseIntOutOfRange :: Property
prop_workFactorParser_cannotParseIntOutOfRange = property $ do
  n <- forAll $ Gen.word Range.linearBounded
  let encoded = toStrictByteString (Builder.wordDec n)
  case parseOnly workFactorParser encoded of
    Left _
      | n <= 0 || n > 64 -> pure ()
      | otherwise -> fail $ "failed when parsing " <> show n
    Right _
      | n > 0 && n <= 64 -> pure ()
      | otherwise -> fail $ "succeeded when parsing " <> show n

prop_golden_workFactor :: Property
prop_golden_workFactor =
  goldenTestWithEncoderAndDecoder
    (toStrictByteString . workFactorBuilder)
    (parseOnly workFactorParser)
    goldenWorkFactor
    "test/golden/binary/work-factor/golden.bin"

------------------------------------------------------------------------------
-- Golden examples
------------------------------------------------------------------------------

goldenWorkFactor :: WorkFactor
goldenWorkFactor =
  case mkWorkFactor 13 of
    Nothing -> error "goldenWorkFactor: impossible: could not construct work factor"
    Just x -> x

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

toStrictByteString :: Builder -> ByteString
toStrictByteString = BS.toStrict . toLazyByteString
