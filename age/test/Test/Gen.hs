module Test.Gen
  ( genByteArray
  ) where

import Prelude

import Data.ByteArray ( ByteArray )
import qualified Data.ByteArray as BA
import Hedgehog ( Gen, Range )
import qualified Hedgehog.Gen as Gen

genByteArray :: ByteArray ba => Range Int -> Gen ba
genByteArray range = BA.convert <$> Gen.bytes range
