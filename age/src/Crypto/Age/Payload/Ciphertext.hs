{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE PatternSynonyms #-}

-- | Encrypted chunks of an age file payload.
module Crypto.Age.Payload.Ciphertext
  ( -- * Encrypted payload chunk
    CiphertextPayloadChunk (..)
  , ciphertextPayloadChunkToBytes
  , ciphertextPayloadChunkParser
    -- ** Normal chunk
  , NormalCiphertextPayloadChunk (NormalCiphertextPayloadChunk)
  , mkNormalCiphertextPayloadChunk
  , normalCiphertextPayloadChunkParser
    -- ** Final chunk
  , FinalCiphertextPayloadChunk (FinalCiphertextPayloadChunk)
  , mkFinalCiphertextPayloadChunk
  , finalCiphertextPayloadChunkParser
  ) where

import Control.Applicative ( Alternative (..) )
import Control.Monad ( void )
import Crypto.Age.Payload.Plaintext ( plaintextChunkSize )
import Data.Attoparsec.ByteString ( Parser, atEnd, endOfInput, take )
import Data.Attoparsec.ByteString.Extra ( takeWhileMN )
import Data.ByteArray ( constEq )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Prelude hiding ( take )

authenticationTagSize :: Int
authenticationTagSize = 16

ciphertextChunkSize :: Int
ciphertextChunkSize = plaintextChunkSize + authenticationTagSize

-------------------------------------------------------------------------------
-- Normal encrypted payload chunk
-------------------------------------------------------------------------------

-- | Normal chunk of data in an encrypted payload (i.e. not the final chunk).
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
newtype NormalCiphertextPayloadChunk = MkNormalCiphertextPayloadChunk
  { unNormalCiphertextPayloadChunk :: ByteString }
  deriving newtype (Show)

instance Eq NormalCiphertextPayloadChunk where
  MkNormalCiphertextPayloadChunk x == MkNormalCiphertextPayloadChunk y = x `constEq` y

pattern NormalCiphertextPayloadChunk :: ByteString -> NormalCiphertextPayloadChunk
pattern NormalCiphertextPayloadChunk bs <- MkNormalCiphertextPayloadChunk bs

{-# COMPLETE NormalCiphertextPayloadChunk #-}

-- | Construct a 64 KiB encrypted payload chunk from a byte string.
mkNormalCiphertextPayloadChunk :: ByteString -> Maybe NormalCiphertextPayloadChunk
mkNormalCiphertextPayloadChunk bs
  | BS.length bs == ciphertextChunkSize = Just (MkNormalCiphertextPayloadChunk bs)
  | otherwise = Nothing

normalCiphertextPayloadChunkParser :: Parser NormalCiphertextPayloadChunk
normalCiphertextPayloadChunkParser = do
  bs <- take ciphertextChunkSize
  atEnd >>= \case
    True -> fail "expected more input"
    False -> pure (MkNormalCiphertextPayloadChunk bs)

-------------------------------------------------------------------------------
-- Final encrypted payload chunk
-------------------------------------------------------------------------------

-- | Final chunk of data in an encrypted payload.
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
newtype FinalCiphertextPayloadChunk = MkFinalCiphertextPayloadChunk
  { unFinalCiphertextPayloadChunk :: ByteString }
  deriving newtype (Show)

instance Eq FinalCiphertextPayloadChunk where
  MkFinalCiphertextPayloadChunk x == MkFinalCiphertextPayloadChunk y = x `constEq` y

pattern FinalCiphertextPayloadChunk :: ByteString -> FinalCiphertextPayloadChunk
pattern FinalCiphertextPayloadChunk bs <- MkFinalCiphertextPayloadChunk bs

{-# COMPLETE FinalCiphertextPayloadChunk #-}

-- | Construct the final chunk of data in a payload from a byte string that is
-- 64 KiB or smaller.
mkFinalCiphertextPayloadChunk :: ByteString -> Maybe FinalCiphertextPayloadChunk
mkFinalCiphertextPayloadChunk bs
  | bsLen >= authenticationTagSize && bsLen <= ciphertextChunkSize =
      Just (MkFinalCiphertextPayloadChunk bs)
  | otherwise = Nothing
  where
    bsLen :: Int
    bsLen = BS.length bs

finalCiphertextPayloadChunkParser :: Parser FinalCiphertextPayloadChunk
finalCiphertextPayloadChunkParser = do
  bs <-
    takeWhileMN
      (fromIntegral authenticationTagSize)
      (fromIntegral ciphertextChunkSize)
      (const True)
  void endOfInput
  pure (MkFinalCiphertextPayloadChunk bs)

-------------------------------------------------------------------------------
-- Encrypted payload chunk
-------------------------------------------------------------------------------

-- | Chunk of data in an encrypted payload.
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
data CiphertextPayloadChunk
  = -- | Normal chunk of ciphertext (i.e. not the final chunk).
    CiphertextPayloadChunkNormal !NormalCiphertextPayloadChunk
  | -- | Final chunk of ciphertext.
    CiphertextPayloadChunkFinal !FinalCiphertextPayloadChunk
  deriving stock (Show, Eq)

ciphertextPayloadChunkToBytes :: CiphertextPayloadChunk -> ByteString
ciphertextPayloadChunkToBytes = \case
  CiphertextPayloadChunkNormal c -> unNormalCiphertextPayloadChunk c
  CiphertextPayloadChunkFinal c -> unFinalCiphertextPayloadChunk c

ciphertextPayloadChunkParser :: Parser CiphertextPayloadChunk
ciphertextPayloadChunkParser =
  (CiphertextPayloadChunkNormal <$> normalCiphertextPayloadChunkParser)
    <|> (CiphertextPayloadChunkFinal <$> finalCiphertextPayloadChunkParser)
