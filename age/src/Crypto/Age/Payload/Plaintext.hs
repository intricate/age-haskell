{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE PatternSynonyms #-}

-- | Plaintext chunks of an age file payload.
module Crypto.Age.Payload.Plaintext
  ( -- * Plaintext payload chunk
    PlaintextPayloadChunk (..)
  , plaintextPayloadChunkToBytes
  , plaintextPayloadChunkParser
  , plaintextChunkSize
    -- ** Normal chunk
  , NormalPlaintextPayloadChunk (NormalPlaintextPayloadChunk)
  , mkNormalPlaintextPayloadChunk
  , normalPlaintextPayloadChunkParser
    -- ** Final chunk
  , FinalPlaintextPayloadChunk (FinalPlaintextPayloadChunk)
  , mkFinalPlaintextPayloadChunk
  , finalPlaintextPayloadChunkParser
  ) where

import Control.Applicative ( Alternative (..) )
import Control.Monad ( void )
import Data.Attoparsec.ByteString ( Parser, atEnd, endOfInput, take )
import Data.Attoparsec.ByteString.Extra ( takeWhileMN )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Prelude hiding ( take )

-- | Size of a full plaintext payload chunk (64 KiB).
plaintextChunkSize :: Int
plaintextChunkSize = 64 * 1024

-------------------------------------------------------------------------------
-- Normal plaintext payload chunk
-------------------------------------------------------------------------------

-- | Normal chunk of plaintext data in a payload (i.e. not the final chunk).
newtype NormalPlaintextPayloadChunk = MkNormalPlaintextPayloadChunk
  { unNormalPlaintextPayloadChunk :: ByteString }
  deriving newtype (Show, Eq)

pattern NormalPlaintextPayloadChunk :: ByteString -> NormalPlaintextPayloadChunk
pattern NormalPlaintextPayloadChunk bs <- MkNormalPlaintextPayloadChunk bs

{-# COMPLETE NormalPlaintextPayloadChunk #-}

-- | Construct a 64 KiB plaintext payload chunk from a byte string.
mkNormalPlaintextPayloadChunk :: ByteString -> Maybe NormalPlaintextPayloadChunk
mkNormalPlaintextPayloadChunk bs
  | BS.length bs == plaintextChunkSize = Just (MkNormalPlaintextPayloadChunk bs)
  | otherwise = Nothing

normalPlaintextPayloadChunkParser :: Parser NormalPlaintextPayloadChunk
normalPlaintextPayloadChunkParser = do
  bs <- take plaintextChunkSize
  atEnd >>= \case
    True -> fail "expected more input"
    False -> pure (MkNormalPlaintextPayloadChunk bs)

-------------------------------------------------------------------------------
-- Final plaintext payload chunk
-------------------------------------------------------------------------------

-- | Final chunk of plaintext data in a payload.
newtype FinalPlaintextPayloadChunk = MkFinalPlaintextPayloadChunk
  { unFinalPlaintextPayloadChunk :: ByteString }
  deriving newtype (Show, Eq)

pattern FinalPlaintextPayloadChunk :: ByteString -> FinalPlaintextPayloadChunk
pattern FinalPlaintextPayloadChunk bs <- MkFinalPlaintextPayloadChunk bs

{-# COMPLETE FinalPlaintextPayloadChunk #-}

-- | Construct the final chunk of data in a payload from a byte string that is
-- 64 KiB or smaller.
mkFinalPlaintextPayloadChunk :: ByteString -> Maybe FinalPlaintextPayloadChunk
mkFinalPlaintextPayloadChunk bs
  | BS.length bs <= plaintextChunkSize = Just (MkFinalPlaintextPayloadChunk bs)
  | otherwise = Nothing

finalPlaintextPayloadChunkParser :: Parser FinalPlaintextPayloadChunk
finalPlaintextPayloadChunkParser = do
  bs <- takeWhileMN 0 (fromIntegral plaintextChunkSize) (const True)
  void endOfInput
  pure (MkFinalPlaintextPayloadChunk bs)

-------------------------------------------------------------------------------
-- Plaintext payload chunk
-------------------------------------------------------------------------------

-- | Chunk of data in an plaintext payload.
data PlaintextPayloadChunk
  = -- | Normal chunk of plaintext (i.e. not the final chunk).
    PlaintextPayloadChunkNormal !NormalPlaintextPayloadChunk
  | -- | Final chunk of plaintext.
    PlaintextPayloadChunkFinal !FinalPlaintextPayloadChunk
  deriving stock (Show, Eq)

plaintextPayloadChunkToBytes :: PlaintextPayloadChunk -> ByteString
plaintextPayloadChunkToBytes = \case
  PlaintextPayloadChunkNormal c -> unNormalPlaintextPayloadChunk c
  PlaintextPayloadChunkFinal c -> unFinalPlaintextPayloadChunk c

plaintextPayloadChunkParser :: Parser PlaintextPayloadChunk
plaintextPayloadChunkParser =
  (PlaintextPayloadChunkNormal <$> normalPlaintextPayloadChunkParser)
    <|> (PlaintextPayloadChunkFinal <$> finalPlaintextPayloadChunkParser)
