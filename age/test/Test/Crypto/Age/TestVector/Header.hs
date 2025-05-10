{-# LANGUAGE LambdaCase #-}

module Test.Crypto.Age.TestVector.Header
  ( Expect (..)
  , Compressed (..)
  , Header (..)
  , headerParser
  ) where

import Control.Monad ( void )
import Crypto.Age.Identity
  ( Identity (..), ScryptIdentity (..), X25519Identity, decodeX25519Identity )
import Crypto.Age.Scrypt ( Passphrase (..), WorkFactor (..), mkWorkFactor )
import qualified Crypto.Hash as Crypto
import Data.Attoparsec.ByteString
  ( Parser, many1', notInClass, skipWhile, takeTill, takeWhile )
import Data.Attoparsec.ByteString.Char8
  ( char8, endOfLine, isEndOfLine, isHorizontalSpace )
import Data.Base16.Types ( Base16, assertBase16 )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import Data.ByteString.Base16 ( decodeBase16Untyped, isValidBase16 )
import Data.Foldable ( foldl' )
import Data.Text ( Text )
import qualified Data.Text.Encoding as TE
import Data.Word ( Word8 )
import Prelude hiding ( takeWhile )

data Expect
  = ExpectSuccess
  | ExpectNoMatch
  | ExpectHmacFailure
  | ExpectHeaderFailure
  | ExpectPayloadFailure
  | ExpectArmorFailure
  deriving stock (Show)

parseExpect :: ByteString -> Maybe Expect
parseExpect = \case
  "success" -> Just ExpectSuccess
  "no match" -> Just ExpectNoMatch
  "HMAC failure" -> Just ExpectHmacFailure
  "header failure" -> Just ExpectHeaderFailure
  "payload failure" -> Just ExpectPayloadFailure
  "armor failure" -> Just ExpectArmorFailure
  _ -> Nothing

data Compressed
  = CompressedGzip
  | CompressedZlib
  deriving stock (Show)

parseCompressed :: ByteString -> Maybe Compressed
parseCompressed = \case
  "gzip" -> Just CompressedGzip
  "zlib" -> Just CompressedZlib
  _ -> Nothing

data RawHeaderLine = RawHeaderLine
  { rhlName :: !ByteString
  , rhlValue :: !ByteString
  }

rawHeaderLineParser :: Parser RawHeaderLine
rawHeaderLineParser =
  RawHeaderLine
    <$> (takeWhile isToken <* char8 ':' <* skipWhile isHorizontalSpace)
    <*> (takeTill isEndOfLine <* endOfLine)
  where
    isToken :: Word8 -> Bool
    isToken w = w <= 127 && notInClass "\0-\31()<>@,;:\\\"/[]?={}\t\127" w

data HeaderLine
  = HeaderLineExpect !Expect
  | HeaderLineCompressed !Compressed
  | HeaderLinePayload !(Crypto.Digest Crypto.SHA256)
  | HeaderLineIdentity !X25519Identity
  | HeaderLinePassphrase !Passphrase
  | HeaderLineArmored !Bool
  | HeaderLineFileKey !(Base16 ByteString)
  | HeaderLineComment !Text

fromRawHeaderLine :: RawHeaderLine -> Maybe HeaderLine
fromRawHeaderLine r =
  case rhlName of
    "expect" -> HeaderLineExpect <$> parseExpect rhlValue
    "compressed" -> HeaderLineCompressed <$> parseCompressed rhlValue
    "payload" -> do
      decoded <- eitherToMaybe (decodeBase16Untyped rhlValue)
      HeaderLinePayload <$> (Crypto.digestFromByteString decoded)
    "identity" -> HeaderLineIdentity <$> eitherToMaybe (decodeX25519Identity $ TE.decodeUtf8 rhlValue)
    "passphrase" -> Just . HeaderLinePassphrase . Passphrase $ BA.convert rhlValue
    "armored" ->
      Just $
        case rhlValue of
          "yes" -> HeaderLineArmored True
          _ -> HeaderLineArmored False
    "file key" ->
      if isValidBase16 rhlValue
        then Just $ HeaderLineFileKey (assertBase16 rhlValue)
        else Nothing
    "comment" -> Just $ HeaderLineComment (TE.decodeUtf8 rhlValue)
    _ -> Nothing
  where
    RawHeaderLine
      { rhlName
      , rhlValue
      } = r

    eitherToMaybe :: Either a b -> Maybe b
    eitherToMaybe (Left _) = Nothing
    eitherToMaybe (Right a) = Just a

headerLineParser :: Parser HeaderLine
headerLineParser = do
  line@RawHeaderLine{rhlName, rhlValue} <- rawHeaderLineParser
  case fromRawHeaderLine line of
    Just x -> pure x
    Nothing ->
      fail $
        "failed to parse header line with name "
          <> show (TE.decodeUtf8 rhlName)
          <> " and value: "
          <> show (TE.decodeUtf8 rhlValue)

newtype HeaderLines = HeaderLines
  { unHeaderLines :: [HeaderLine] }

headerLinesParser :: Parser HeaderLines
headerLinesParser = HeaderLines <$> many1' headerLineParser

data HeaderOptions = HeaderOptions
  { hoExpect :: !(Maybe Expect)
  , hoCompressed :: !(Maybe Compressed)
  , hoPayload :: !(Maybe (Crypto.Digest Crypto.SHA256))
  , hoIdentity :: !(Maybe Identity)
  , hoArmored :: !(Maybe Bool)
  , hoFileKey :: !(Maybe (Base16 ByteString))
  , hoComment :: !(Maybe Text)
  }

emptyHeaderOptions :: HeaderOptions
emptyHeaderOptions =
  HeaderOptions
    { hoExpect = Nothing
    , hoCompressed = Nothing
    , hoPayload = Nothing
    , hoIdentity = Nothing
    , hoArmored = Nothing
    , hoFileKey = Nothing
    , hoComment = Nothing
    }

toHeaderOptions :: HeaderLines -> HeaderOptions
toHeaderOptions = foldl' accumHeaderOptions emptyHeaderOptions . unHeaderLines
  where
    -- The test vector, @scrypt_work_factor_23@, expects us to fail given an
    -- scrypt stanza with a work factor of 23.
    --
    -- So we just set our maximum to 22 in order to ensure that we return the
    -- expected error.
    workFactor22 :: WorkFactor
    workFactor22 =
      case mkWorkFactor 22 of
        Just x -> x
        Nothing -> error "toHeaderOptions: impossible: could not construct work factor of 22"

    accumHeaderOptions :: HeaderOptions -> HeaderLine -> HeaderOptions
    accumHeaderOptions acc line =
      case line of
        HeaderLineExpect x -> acc { hoExpect = Just x }
        HeaderLineCompressed x -> acc { hoCompressed = Just x }
        HeaderLinePayload x -> acc { hoPayload = Just x }
        HeaderLineIdentity x -> acc { hoIdentity = Just (IdentityX25519 x) }
        HeaderLinePassphrase x -> acc { hoIdentity = Just $ IdentityScrypt (ScryptIdentity x workFactor22) }
        HeaderLineArmored x -> acc { hoArmored = Just x }
        HeaderLineFileKey x -> acc { hoFileKey = Just x }
        HeaderLineComment x -> acc { hoComment = Just x }

data Header = Header
  { hExpect :: !Expect
  , hCompressed :: !(Maybe Compressed)
  , hPayload :: !(Maybe (Crypto.Digest Crypto.SHA256))
  , hIdentity :: !Identity
  , hArmored :: !Bool
  , hFileKey :: !(Maybe (Base16 ByteString))
  , hComment :: !(Maybe Text)
  }

toHeader :: HeaderOptions -> Maybe Header
toHeader h =
  case hoExpect of
    Just expect ->
      Just $
        Header
          { hExpect = expect
          , hCompressed = hoCompressed
          , hPayload = hoPayload
          , hIdentity =
              case hoIdentity of
                Just identity -> identity
                Nothing ->
                  -- There are a couple test vectors where neither an X25519
                  -- identity nor scrypt passphrase are specified:
                  --
                  -- - armor_empty
                  -- - empty
                  --
                  -- These are expected to fail parsing due to being empty, so
                  -- we'll just default to some invalid identity since it
                  -- doesn't matter.
                  defaultIdentity
          , hArmored =
              case hoArmored of
                Just x -> x
                _ -> False
          , hFileKey = hoFileKey
          , hComment = hoComment
          }
    Nothing -> Nothing
  where
    HeaderOptions
      { hoExpect
      , hoCompressed
      , hoPayload
      , hoIdentity
      , hoArmored
      , hoFileKey
      , hoComment
      } = h

    defaultIdentity :: Identity
    defaultIdentity =
      IdentityScrypt $
        ScryptIdentity
          { siPassphrase = Passphrase "aaaa"
          , siMaxWorkFactor = maxBound
          }

headerParser :: Parser Header
headerParser = do
  headerLines <- headerLinesParser
  void endOfLine
  case toHeader (toHeaderOptions headerLines) of
    Just x -> pure x
    Nothing -> fail "Header is missing required fields"
