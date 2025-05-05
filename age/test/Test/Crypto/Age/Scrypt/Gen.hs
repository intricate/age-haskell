module Test.Crypto.Age.Scrypt.Gen
  ( genPassphrase
  , genSalt
  , genWorkFactorInRange
  , genWorkFactor
  ) where

import Crypto.Age.Scrypt
  ( Passphrase (..), Salt, WorkFactor, bytesToSalt, mkWorkFactor )
import Data.Word ( Word8 )
import Hedgehog ( Gen, Range )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Gen ( genByteArray )

genPassphrase :: Gen Passphrase
genPassphrase = Passphrase <$> genByteArray (Range.constant 0 64)

genSalt :: Gen Salt
genSalt = do
  bs <- genByteArray (Range.singleton 16)
  case bytesToSalt bs of
    Nothing -> fail "failed to generate a Salt"
    Just x -> pure x

-- | Generate a 'WorkFactor' in the specified range.
--
-- Note that you should take care when generating large 'WorkFactor's as it can
-- cause @scrypt@ to commit large amounts of memory.
--
-- Also note that this generator can fail if you provide a 'Range' outside the
-- interval @[1, 64]@ (a 'WorkFactor' can be constructed with a value in this
-- range).
genWorkFactorInRange :: Range Word8 -> Gen WorkFactor
genWorkFactorInRange range = do
  i <- Gen.word8 range
  case mkWorkFactor i of
    Nothing -> fail "failed to generate a WorkFactor"
    Just x -> pure x

genWorkFactor :: Gen WorkFactor
genWorkFactor =
  -- We limit the work factor to @10@ for testing.
  genWorkFactorInRange (Range.constant 1 10)
