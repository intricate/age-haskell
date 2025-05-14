-- | age file header.
module Crypto.Age.Header
  ( -- * Header
    Header (..)
  , headerBuilder
  , headerParser
    -- ** Stanza
  , Stanza (..)
  , stanzaBuilder
  , stanzaParser
    -- ** Header MAC
  , HeaderMac (..)
  , computeHeaderMac
  , headerMacBuilder
  , headerMacParser
  ) where

import Control.Monad ( void )
import Crypto.Age.Key ( FileKey, fileKeyToBytes )
import qualified Crypto.Hash as Crypto
import qualified Crypto.KDF.HKDF as HKDF
import qualified Crypto.MAC.HMAC as Crypto
import Data.Attoparsec.ByteString
  ( Parser, many', many1', sepBy1', string, take, takeWhile1 )
import Data.Attoparsec.ByteString.Base64 ( takeMNBase64Chars, takeNBase64Chars )
import Data.Attoparsec.ByteString.Char8 ( char8 )
import Data.ByteArray ( ScrubbedBytes, constEq )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.ByteString.Base64.Extra
  ( decodeBase64StdUnpadded, encodeBase64StdUnpadded )
import Data.ByteString.Builder ( Builder )
import qualified Data.ByteString.Builder as Builder
import Data.ByteString.Extra ( chunksOf )
import Data.Foldable ( foldMap' )
import qualified Data.List as L
import Data.List.NonEmpty ( NonEmpty )
import qualified Data.List.NonEmpty as NE
import qualified Data.Text as T
import Prelude hiding ( take )

-- | Parse an ABNF @VCHAR@ string as specified in
-- [RFC 2234 section 6.1](https://www.rfc-editor.org/rfc/rfc2234#section-6.1).
vcharStringParser :: Parser ByteString
vcharStringParser = takeWhile1 (`elem` [0x21 .. 0x7E])

-- | Parse and decode @n@ characters of unpadded base64.
base64UnpaddedParser :: Int -> Parser ByteString
base64UnpaddedParser n = do
  b64 <- take n
  case decodeBase64StdUnpadded b64 of
    Left err -> fail (T.unpack err)
    Right bs -> pure bs

-- | Stanza.
data Stanza = Stanza
  { -- | Stanza tag (technically, the first argument of the stanza).
    sTag :: !ByteString
  , -- | Stanza arguments (every argument after the tag).
    sArgs :: ![ByteString]
  , -- | Base64-decoded stanza body.
    sBody :: !ByteString
  }
  deriving stock (Show, Eq)

stanzaBegin :: ByteString
stanzaBegin = "-> "

stanzaBuilder :: Stanza -> Builder
stanzaBuilder s = argLineBuilder <> bodyBuilder
  where
    Stanza
      { sTag
      , sArgs
      , sBody
      } = s

    bodyB64 :: ByteString
    bodyB64 = encodeBase64StdUnpadded sBody

    bodyB64Chunks :: [ByteString]
    bodyB64Chunks = chunksOf 64 bodyB64

    argLineBuilder :: Builder
    argLineBuilder =
      Builder.byteString stanzaBegin
        <> Builder.byteString (BS.intercalate " " (sTag : sArgs))
        <> Builder.byteString "\n"

    fullBodyLinesBuilder :: [ByteString] -> Builder
    fullBodyLinesBuilder [] = mempty
    fullBodyLinesBuilder xs =
      Builder.byteString (BS.intercalate "\n" xs)
        <> Builder.byteString "\n"

    finalBodyLineBuilder :: ByteString -> Builder
    finalBodyLineBuilder bs
      | BS.length bs == 64 = Builder.byteString (bs <> "\n\n")
      | otherwise = Builder.byteString (bs <> "\n")

    bodyBuilder :: Builder
    bodyBuilder =
      case L.unsnoc bodyB64Chunks of
        Nothing -> Builder.byteString "\n"
        Just (cs, c) ->
          fullBodyLinesBuilder cs
            <> finalBodyLineBuilder c

stanzaParser :: Parser Stanza
stanzaParser = do
  void $ string stanzaBegin
  (tag, args) <- argLineParser
  void $ char8 '\n'
  body <- bodyParser
  pure Stanza
    { sTag = tag
    , sArgs = args
    , sBody = body
    }
  where
    argLineParser :: Parser (ByteString, [ByteString])
    argLineParser = do
      args <- vcharStringParser `sepBy1'` char8 ' '
      case L.uncons args of
        Nothing -> error "stanzaParser: impossible: no elements in a list parsed using sepBy1"
        Just (tag, rest) -> pure (tag, rest)

    fullBodyLineParser :: Parser ByteString
    fullBodyLineParser = takeNBase64Chars 64 <* char8 '\n'

    finalBodyLineParser :: Parser ByteString
    finalBodyLineParser = takeMNBase64Chars 0 63 <* char8 '\n'

    -- Parse the line-wrapped base64-encoded stanza body.
    --
    -- This parser returns each base64-encoded line of the stanza body.
    wrappedBodyParser :: Parser [ByteString]
    wrappedBodyParser = do
      fullLines <- many' fullBodyLineParser
      finalLine <- finalBodyLineParser
      pure $ fullLines ++ [finalLine]

    -- Parse and decode the stanza body.
    --
    -- This parses each base64-encoded line of the stanza body, concatenates
    -- them, and then base64 decodes the result.
    bodyParser :: Parser ByteString
    bodyParser = do
      bodyLines <- wrappedBodyParser
      case decodeBase64StdUnpadded (BS.concat bodyLines) of
        Left err -> fail (T.unpack err)
        Right bs -> pure bs

-- | Header MAC.
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
newtype HeaderMac = HeaderMac
  { unHeaderMac :: Crypto.HMAC Crypto.SHA256 }

instance Show HeaderMac where
  show = show . Crypto.hmacGetDigest . unHeaderMac

instance Eq HeaderMac where
  HeaderMac x == HeaderMac y = x `constEq` y

-- | Compute the 'HeaderMac' for a 'Header' which would contain the provided 'Stanza's.
computeHeaderMac :: FileKey -> NonEmpty Stanza -> HeaderMac
computeHeaderMac fk stanzas = do
  let info :: ByteString
      info = "header"

      prk :: HKDF.PRK Crypto.SHA256
      prk = HKDF.extract BS.empty (fileKeyToBytes fk)

      hmacKey :: ScrubbedBytes
      hmacKey = HKDF.expand prk info 32

      partialHeaderBs :: ByteString
      partialHeaderBs =
        BS.toStrict . Builder.toLazyByteString $
          headerBuilder' (PartialHeader stanzas) Nothing

  HeaderMac (Crypto.hmac hmacKey partialHeaderBs)

headerMacMark :: ByteString
headerMacMark = "---"

headerMacBegin :: ByteString
headerMacBegin = headerMacMark <> " "

headerMacBuilder :: HeaderMac -> Builder
headerMacBuilder (HeaderMac h) =
  Builder.byteString headerMacBegin
    <> Builder.byteString (encodeBase64StdUnpadded . BA.convert $ Crypto.hmacGetDigest h)

headerMacParser :: Parser HeaderMac
headerMacParser = do
  void $ string headerMacBegin
  macBs <- base64UnpaddedParser 43
  case Crypto.digestFromByteString macBs of
    Nothing -> fail "invalid header HMAC"
    Just d -> pure $ HeaderMac (Crypto.HMAC d)

-- | Partial header.
--
-- This is an internal data type used for computing the header MAC.
newtype PartialHeader = PartialHeader (NonEmpty Stanza)
  deriving stock (Show, Eq)

-- | Convert a 'Header' to a 'PartialHeader'.
toPartialHeader :: Header -> PartialHeader
toPartialHeader Header{hStanzas} = PartialHeader hStanzas

-- | Header.
data Header = Header
  { -- | Stanzas.
    hStanzas :: !(NonEmpty Stanza)
  , -- | Header MAC.
    --
    -- Note that the value of this field is /not/ guaranteed to be
    -- cryptographically verified. For example, if this value was constructed
    -- as the result of parsing an age file, that only means that the value was
    -- deemed to be /syntactically/ valid. It does not mean that it was
    -- verified to be /cryptographically/ valid.
    hMac :: !HeaderMac
  } deriving stock (Show, Eq)

headerVersionLine :: ByteString
headerVersionLine = "age-encryption.org/v1\n"

-- | Encoder which can either encode a partial header (i.e. one with no MAC;
-- which is used for computing the MAC) or a full header (i.e. one with a MAC).
--
-- Note that this function is not intended to be exported.
headerBuilder' :: PartialHeader -> Maybe HeaderMac -> Builder
headerBuilder' (PartialHeader stanzas) mbHeaderMac =
  Builder.byteString headerVersionLine
    <> foldMap' stanzaBuilder stanzas
    <> case mbHeaderMac of
      Just m -> headerMacBuilder m <> Builder.byteString "\n"
      Nothing -> Builder.byteString headerMacMark

-- | 'Header' encoder.
headerBuilder :: Header -> Builder
headerBuilder h@Header{hMac} =
  headerBuilder' (toPartialHeader h) (Just hMac)

-- | 'Header' parser.
headerParser :: Parser Header
headerParser = do
  void $ string headerVersionLine
  stanzas <- many1' stanzaParser
  nonEmptyStanzas <-
    case NE.nonEmpty stanzas of
      Nothing -> fail "expecting one or more recipient stanzas"
      Just x -> pure x
  mac <- headerMacParser
  void $ char8 '\n'
  pure Header
    { hStanzas = nonEmptyStanzas
    , hMac = mac
    }
