module Test.Crypto.Age.Payload.Counter.Gen
  ( genPayloadChunkCounter
  ) where

import Crypto.Age.Payload.Counter
  ( PayloadChunkCounter, maxPayloadChunkCounter, mkPayloadChunkCounter )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude

genPayloadChunkCounter :: Gen PayloadChunkCounter
genPayloadChunkCounter = do
  i <- Gen.integral (Range.constant 0 maxPayloadChunkCounter)
  case mkPayloadChunkCounter i of
    Nothing -> fail "failed to generate a PayloadChunkCounter"
    Just x -> pure x
