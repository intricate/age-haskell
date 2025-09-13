module Data.Attoparsec.ByteString.Base64
  ( isBase64Char
  , base64CharParser
  , takeNBase64Chars
  , takeMNBase64Chars
  ) where

import Data.Attoparsec.ByteString ( Parser, count, inClass, satisfy, (<?>) )
import Data.Attoparsec.ByteString.Extra ( takeWhileMN )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.Word ( Word8 )
import Prelude

-- | Determine whether a 'Word8' is a valid character in an unpadded base64
-- string.
isBase64Char :: Word8 -> Bool
isBase64Char = inClass "a-zA-Z0-9+/"

-- | Parse a base64 character.
base64CharParser :: Parser Word8
base64CharParser = satisfy isBase64Char <?> "base64 character"

-- | Consume exactly @n@ base64 characters.
takeNBase64Chars :: Word -> Parser ByteString
takeNBase64Chars n = BS.pack <$> count (fromIntegral n) base64CharParser

-- | Consume a base64 character string of length @m <= len <= n@.
takeMNBase64Chars ::
  -- | @m@.
  Word ->
  -- | @n@.
  Word ->
  Parser ByteString
takeMNBase64Chars m n = takeWhileMN m n isBase64Char
