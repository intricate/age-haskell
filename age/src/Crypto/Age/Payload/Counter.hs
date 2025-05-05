{-# LANGUAGE LambdaCase #-}

-- | @ChaCha20-Poly1305@ counter nonces for decrypting chunks of an age file
-- payload.
module Crypto.Age.Payload.Counter
  ( PayloadChunkCounter
  , unPayloadChunkCounter
  , mkPayloadChunkCounter
  , zeroPayloadChunkCounter
  , incrementPayloadChunkCounter
  , maxPayloadChunkCounter
  , IsFinalChunk (..)
  , toChaCha20Poly1305Nonce
  ) where

import qualified Crypto.Cipher.ChaChaPoly1305 as ChaCha20Poly1305
import qualified Crypto.Error as Crypto
import Data.Binary.Put ( runPut )
import Data.Binary.Put.Integer ( putIntegerbe )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.Word ( Word8 )
import Prelude

-- | Maximum payload chunk counter value (@0xFFFFFFFFFFFFFFFFFFFFFF@, i.e. the
-- maximum integer value that can be stored in 11 bytes).
maxPayloadChunkCounter :: Integer
maxPayloadChunkCounter = 0xFFFFFFFFFFFFFFFFFFFFFF

-- | Payload chunk counter.
newtype PayloadChunkCounter = MkPayloadChunkCounter
  { unPayloadChunkCounter :: Integer }
  deriving newtype (Show, Eq)

-- | Construct a 'PayloadChunkCounter'.
--
-- Note that, if the provided 'Integer' value is less than @0@ or greater than
-- @0xFFFFFFFFFFFFFFFFFFFFFF@ (i.e. the maximum integer value that can be
-- stored in 11 bytes), this function will return 'Nothing'.
mkPayloadChunkCounter :: Integer -> Maybe PayloadChunkCounter
mkPayloadChunkCounter x
  | x >= 0 && x <= maxPayloadChunkCounter = Just (MkPayloadChunkCounter x)
  | otherwise = Nothing

-- | Construct a 'PayloadChunkCounter' initialized to @0@.
zeroPayloadChunkCounter :: PayloadChunkCounter
zeroPayloadChunkCounter = MkPayloadChunkCounter 0

-- | Increment a 'PayloadChunkCounter' by @1@.
--
-- Note that, if this operation would result in a 'PayloadChunkCounter' that is
-- greater than @0xFFFFFFFFFFFFFFFFFFFFFF@ (i.e. the maximum integer value that
-- can be stored in 11 bytes), this function will return 'Nothing'.
incrementPayloadChunkCounter :: PayloadChunkCounter -> Maybe PayloadChunkCounter
incrementPayloadChunkCounter (MkPayloadChunkCounter x)
  | x < maxPayloadChunkCounter = Just (MkPayloadChunkCounter $ x + 1)
  | otherwise = Nothing

-- | Encode a 'PayloadChunkCounter' as an 11-byte integer in big endian format.
payloadChunkCounterToBytes :: PayloadChunkCounter -> ByteString
payloadChunkCounterToBytes (MkPayloadChunkCounter counter) = counterBs
 where
  padTo :: Int -> ByteString -> ByteString
  padTo n bs
    | n <= 0 = bs
    | BS.length bs >= n = bs
    | otherwise = BS.replicate (n - BS.length bs) 0 <> bs

  counterBs :: ByteString
  counterBs = padTo 11 $ BS.toStrict $ runPut (putIntegerbe counter)

-- | Whether this is the final payload chunk.
data IsFinalChunk
  = -- | This is the final payload chunk.
    IsFinalChunk
  | -- | This is not the final payload chunk.
    IsNotFinalChunk
  deriving stock (Show, Eq)

-- | Encode a 'PayloadChunkCounter' as a 12-byte 'ChaCha20Poly1305.Nonce'.
toChaCha20Poly1305Nonce :: IsFinalChunk -> PayloadChunkCounter -> ChaCha20Poly1305.Nonce
toChaCha20Poly1305Nonce isFinalChunk counter = nonce
  where
    finalByte :: Word8
    finalByte =
      case isFinalChunk of
        IsFinalChunk -> 0x01
        IsNotFinalChunk -> 0x00

    counterBs :: ByteString
    counterBs = payloadChunkCounterToBytes counter

    nonceBs :: ByteString
    nonceBs = counterBs <> BS.singleton finalByte

    nonce :: ChaCha20Poly1305.Nonce
    nonce =
      case ChaCha20Poly1305.nonce12 nonceBs of
        Crypto.CryptoFailed _ -> error "toChaCha20Poly1305Nonce: impossible: could not construct nonce from 12 bytes"
        Crypto.CryptoPassed n -> n
