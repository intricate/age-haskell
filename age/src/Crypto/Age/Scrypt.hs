{-# LANGUAGE PatternSynonyms #-}

-- | @scrypt@-related types and utilities.
module Crypto.Age.Scrypt
  ( -- * Passphrase
    Passphrase (..)

    -- * Salt
  , Salt (Salt)
  , bytesToSalt
  , saltToBytes

    -- * Work factor
  , WorkFactor (WorkFactor)
  , unWorkFactor
  , mkWorkFactor
  , workFactorBuilder
  , workFactorParser
  ) where

import Control.Monad ( when )
import Data.Attoparsec.ByteString ( Parser, endOfInput, peekWord8' )
import Data.Attoparsec.ByteString.Char8 ( decimal )
import Data.ByteArray ( ScrubbedBytes )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.ByteString.Builder ( Builder )
import qualified Data.ByteString.Builder as Builder
import Data.Word ( Word8 )
import Prelude

-- | @scrypt@ passphrase.
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
newtype Passphrase = Passphrase
  { unPassphrase :: ScrubbedBytes }
  deriving newtype (Show, Eq)

-- | @scrypt@ salt.
newtype Salt = MkSalt
  { unSalt :: ByteString }
  deriving newtype (Show, Eq)

pattern Salt :: ByteString -> Salt
pattern Salt bs <- MkSalt bs

{-# COMPLETE Salt #-}

-- | Construct a 'Salt' from bytes.
--
-- If the provided byte string does not have a length of 16 (128 bits),
-- 'Nothing' is returned.
bytesToSalt :: ByteString -> Maybe Salt
bytesToSalt bs
  | BS.length bs == 16 = Just (MkSalt bs)
  | otherwise = Nothing

-- | Get the raw bytes associated with a 'Salt'.
saltToBytes :: Salt -> ByteString
saltToBytes = unSalt

-- | Minimum work factor (@1@).
minWorkFactor :: Word8
minWorkFactor = 1

-- | Maximum work factor (@64@).
maxWorkFactor :: Word8
maxWorkFactor = 64

-- | @scrypt@ \"work factor\" (as it is referred to in the age specification).
--
-- This value is used in calculating the
-- [@scrypt@ cost parameter (also referred to as @N@)](https://www.rfc-editor.org/rfc/rfc7914#section-2):
--
-- > N = 2 ^ work_factor
newtype WorkFactor = MkWorkFactor
  { unWorkFactor :: Word8 }
  deriving newtype (Show, Eq)

instance Bounded WorkFactor where
  minBound = MkWorkFactor minWorkFactor
  maxBound = MkWorkFactor maxWorkFactor

pattern WorkFactor :: Word8 -> WorkFactor
pattern WorkFactor w8 <- MkWorkFactor w8

{-# COMPLETE WorkFactor #-}

-- | Construct a 'WorkFactor' value.
--
-- If the provided value is @0@ or greater than @64@, this function will return
-- 'Nothing'.
mkWorkFactor :: Word8 -> Maybe WorkFactor
mkWorkFactor w8
  | w8 >= minWorkFactor && w8 <= maxWorkFactor = Just (MkWorkFactor w8)
  | otherwise = Nothing

-- | 'WorkFactor' encoder.
workFactorBuilder :: WorkFactor -> Builder
workFactorBuilder = Builder.word8Dec . unWorkFactor

-- | 'WorkFactor' parser.
workFactorParser :: Parser WorkFactor
workFactorParser = do
  firstByte <- peekWord8'
  when (firstByte == 0x30) $
    -- Leading zeroes are disallowed
    fail "expected digit from 1 to 9"

  parsedDigits <- decimal <* endOfInput :: Parser Integer
  when (parsedDigits <= 0) $
    fail "expected integer greater than 0"
  when (parsedDigits > 64) $
    fail "expected integer less than 65"
  pure $ MkWorkFactor (fromIntegral parsedDigits)
