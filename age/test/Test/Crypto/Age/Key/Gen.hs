module Test.Crypto.Age.Key.Gen
  ( genFileKey
  , genPayloadKeyNonce
  , genPayloadKey
  ) where

import Crypto.Age.Key
  ( FileKey
  , PayloadKey
  , PayloadKeyNonce
  , bytesToFileKey
  , bytesToPayloadKey
  , bytesToPayloadKeyNonce
  )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Gen ( genByteArray )

genFileKey :: Gen FileKey
genFileKey = do
  bs <- genByteArray (Range.singleton 16)
  case bytesToFileKey bs of
    Nothing -> fail "failed to generate a FileKey"
    Just x -> pure x

genPayloadKeyNonce :: Gen PayloadKeyNonce
genPayloadKeyNonce = do
  bs <- Gen.bytes (Range.singleton 16)
  case bytesToPayloadKeyNonce bs of
    Nothing -> fail "failed to generate a PayloadKeyNonce"
    Just x -> pure x

genPayloadKey :: Gen PayloadKey
genPayloadKey = do
  bs <- genByteArray (Range.singleton 32)
  case bytesToPayloadKey bs of
    Nothing -> fail "failed to generate a PayloadKey"
    Just x -> pure x
