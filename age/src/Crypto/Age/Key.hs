{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE PatternSynonyms #-}

-- | age cryptographic keys.
module Crypto.Age.Key
  ( -- * File key
    FileKey (FileKey)
  , bytesToFileKey
  , fileKeyToBytes
  , generateFileKey

    -- * Payload key nonce
  , PayloadKeyNonce (PayloadKeyNonce)
  , bytesToPayloadKeyNonce
  , payloadKeyNonceToBytes
  , generatePayloadKeyNonce
  , payloadKeyNonceBuilder
  , payloadKeyNonceParser

    -- * Payload key
  , PayloadKey (PayloadKey)
  , bytesToPayloadKey
  , payloadKeyToBytes
  , mkPayloadKey
  ) where

import qualified Crypto.Hash as Crypto
import qualified Crypto.KDF.HKDF as Crypto
import qualified Crypto.Random as Crypto
import Data.Attoparsec.ByteString ( Parser, take )
import Data.ByteArray ( ScrubbedBytes )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.ByteString.Builder ( Builder )
import qualified Data.ByteString.Builder as Builder
import Prelude hiding ( take )

-- | Symmetric
-- [file key](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#file-key).
--
-- Note that this type's 'Eq' instance performs a constant-time equality check.
newtype FileKey = MkFileKey
  { unFileKey :: ScrubbedBytes }
  deriving newtype (Eq)

pattern FileKey :: ScrubbedBytes -> FileKey
pattern FileKey bs <- MkFileKey bs

{-# COMPLETE FileKey #-}

-- | Construct a 'FileKey' from bytes.
--
-- If the provided byte string does not have a length of 16 (128 bits),
-- 'Nothing' is returned.
bytesToFileKey :: ScrubbedBytes -> Maybe FileKey
bytesToFileKey bs
  | BA.length bs == 16 = Just (MkFileKey bs)
  | otherwise = Nothing

-- | Get the raw bytes associated with a 'FileKey'.
fileKeyToBytes :: FileKey -> ScrubbedBytes
fileKeyToBytes = unFileKey

-- | Randomly generate a 'FileKey' as defined in the
-- [age specification](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#file-key).
generateFileKey :: IO FileKey
generateFileKey = do
  bs <- Crypto.getRandomBytes 16 :: IO ScrubbedBytes
  case bytesToFileKey bs of
    Just x -> pure x
    Nothing -> error "generateFileKey: impossible: failed to randomly generate 16 bytes"

-- | Payload key nonce.
--
-- In accordance with the
-- [age specification](https://github.com/C2SP/C2SP/blob/34a9210873230d2acaa4a4c9c5d4d1119b2ee77d/age.md#payload),
-- this value is used as an extractor salt in the @HKDF-Extract@ step when
-- deriving a 'PayloadKey' with @HKDF-SHA256@.
newtype PayloadKeyNonce = MkPayloadKeyNonce
  { unPayloadKeyNonce :: ByteString }
  deriving newtype (Show, Eq)

pattern PayloadKeyNonce :: ByteString -> PayloadKeyNonce
pattern PayloadKeyNonce bs <- MkPayloadKeyNonce bs

{-# COMPLETE PayloadKeyNonce #-}

-- | Construct a 'PayloadKeyNonce' from bytes.
--
-- If the provided byte string does not have a length of 16 (128 bits),
-- 'Nothing' is returned.
bytesToPayloadKeyNonce :: ByteString -> Maybe PayloadKeyNonce
bytesToPayloadKeyNonce bs
  | BS.length bs == 16 = Just (MkPayloadKeyNonce bs)
  | otherwise = Nothing

-- | Get the raw bytes associated with a 'PayloadKeyNonce'.
payloadKeyNonceToBytes :: PayloadKeyNonce -> ByteString
payloadKeyNonceToBytes = unPayloadKeyNonce

-- | Randomly generate a 'PayloadKeyNonce' as defined in the
-- [age specification](https://github.com/C2SP/C2SP/blob/34a9210873230d2acaa4a4c9c5d4d1119b2ee77d/age.md#payload).
generatePayloadKeyNonce :: IO PayloadKeyNonce
generatePayloadKeyNonce = do
  bs <- Crypto.getRandomBytes 16 :: IO ByteString
  case bytesToPayloadKeyNonce bs of
    Just x -> pure x
    Nothing -> error "generatePayloadKeyNonce: impossible: failed to randomly generate 16 bytes"

-- | 'PayloadKeyNonce' encoder.
payloadKeyNonceBuilder :: PayloadKeyNonce -> Builder
payloadKeyNonceBuilder = Builder.byteString . payloadKeyNonceToBytes

-- | 'PayloadKeyNonce' parser.
payloadKeyNonceParser :: Parser PayloadKeyNonce
payloadKeyNonceParser = bytesToPayloadKeyNonce <$> take 16 >>= \case
  Just x -> pure x
  Nothing -> error "impossible: could not construct a PayloadKeyNonce from 16 bytes."

-- | Symmetric
-- [payload key](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#payload).
--
-- Note that this type's 'Eq' instance performs a constant-time equality check.
newtype PayloadKey = MkPayloadKey
  { unPayloadKey :: ScrubbedBytes }
  deriving newtype (Eq)

pattern PayloadKey :: ScrubbedBytes -> PayloadKey
pattern PayloadKey bs <- MkPayloadKey bs

{-# COMPLETE PayloadKey #-}

-- | Construct a 'PayloadKey' from bytes.
--
-- If the provided byte string does not have a length of 32 (256 bits),
-- 'Nothing' is returned.
bytesToPayloadKey :: ScrubbedBytes -> Maybe PayloadKey
bytesToPayloadKey bs
  | BA.length bs == 32 = Just (MkPayloadKey bs)
  | otherwise = Nothing

-- | Get the raw bytes associated with a 'PayloadKey'.
payloadKeyToBytes :: PayloadKey -> ScrubbedBytes
payloadKeyToBytes = unPayloadKey

-- | Construct a 'PayloadKey' as defined in the
-- [age specification](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#payload).
--
-- The 'PayloadKey' is derived via @HKDF-SHA256@ given a 'PayloadKeyNonce' as
-- the extractor salt, a 'FileKey' as the input keying material, and the string
-- @payload@ as the expansion context/info.
mkPayloadKey :: PayloadKeyNonce -> FileKey -> PayloadKey
mkPayloadKey nonce fileKey =
  case bytesToPayloadKey (Crypto.expand prk payloadKeyHkdfInfo 32) of
    Just x -> x
    Nothing -> error "mkPayloadKey: impossible: could not construct PayloadKey from 32 bytes"
  where
    payloadKeyHkdfInfo :: ByteString
    payloadKeyHkdfInfo = "payload"

    prk :: Crypto.PRK Crypto.SHA256
    prk = Crypto.extract (unPayloadKeyNonce nonce) (unFileKey fileKey)
