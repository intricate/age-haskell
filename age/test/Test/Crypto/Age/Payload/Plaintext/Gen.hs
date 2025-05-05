module Test.Crypto.Age.Payload.Plaintext.Gen
  ( genNormalPlaintextPayloadChunk
  , genFinalPlaintextPayloadChunk
  , genPlaintextPayloadChunk
  ) where

import Crypto.Age.Payload.Plaintext
  ( FinalPlaintextPayloadChunk
  , NormalPlaintextPayloadChunk
  , PlaintextPayloadChunk (..)
  , mkFinalPlaintextPayloadChunk
  , mkNormalPlaintextPayloadChunk
  , plaintextChunkSize
  )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Gen ( genByteArray )

genNormalPlaintextPayloadChunk :: Gen NormalPlaintextPayloadChunk
genNormalPlaintextPayloadChunk = do
  bs <- genByteArray (Range.singleton plaintextChunkSize)
  case mkNormalPlaintextPayloadChunk bs of
    Nothing -> fail "failed to generate a NormalPlaintextPayloadChunk"
    Just x -> pure x

genFinalPlaintextPayloadChunk :: Gen FinalPlaintextPayloadChunk
genFinalPlaintextPayloadChunk = do
  bs <-
    -- Tend more toward generating smaller chunks.
    Gen.frequency
      [ (1, genByteArray (Range.constant 256 plaintextChunkSize))
      , (30, genByteArray (Range.constant 0 256))
      ]
  case mkFinalPlaintextPayloadChunk bs of
    Nothing -> fail "failed to generate a FinalPlaintextPayloadChunk"
    Just x -> pure x

genPlaintextPayloadChunk :: Gen PlaintextPayloadChunk
genPlaintextPayloadChunk =
  -- Tend more toward generating smaller final chunks rather than full 64 KiB
  -- normal chunks.
  Gen.frequency
    [ (1, PlaintextPayloadChunkNormal <$> genNormalPlaintextPayloadChunk)
    , (30, PlaintextPayloadChunkFinal <$> genFinalPlaintextPayloadChunk)
    ]
