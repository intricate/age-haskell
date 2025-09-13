{-# LANGUAGE LambdaCase #-}

-- | age
-- [ASCII armor](https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#ascii-armor)
-- encoding and decoding.
module Crypto.Age.Armor
  ( -- * Encoding
    ArmorError (..)
  , conduitArmor
    -- * Decoding
  , UnarmorError (..)
  , conduitUnarmor
  ) where

import Control.Applicative ( Alternative (..), optional )
import Control.Monad ( void )
import Control.Monad.Except ( ExceptT, throwError, withExceptT )
import Control.Monad.Trans.Class ( MonadTrans (lift) )
import Data.Attoparsec.ByteString ( Parser, count, endOfInput, string )
import Data.Attoparsec.ByteString.Base64 ( takeNBase64Chars )
import Data.Attoparsec.ByteString.Char8 ( char8, endOfLine, skipSpace )
import Data.Attoparsec.ByteString.Extra ( countMN )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.Conduit ( ConduitT, await, leftover, transPipe, yield, (.|) )
import Data.Conduit.Attoparsec ( ParseError, sinkParserEither )
import Data.Conduit.Base64 ( conduitDecodeBase64, conduitEncodeBase64 )
import qualified Data.Conduit.Combinators as C
import Data.Text ( Text )
import Data.Word ( Word8 )
import Prelude

label :: ByteString
label = "AGE ENCRYPTED FILE"

lineBegin :: ByteString
lineBegin = "-----BEGIN " <> label <> "-----"

lineEnd :: ByteString
lineEnd = "-----END " <> label <> "-----"

-------------------------------------------------------------------------------
-- Encoding
-------------------------------------------------------------------------------

-- | Error
-- \"[armoring](https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#ascii-armor)\"
-- an age file.
data ArmorError
  = -- | No data was provided to be armored (i.e. end of input was reached
    -- without consuming any bytes).
    ArmorNoDataError
  deriving stock (Show, Eq)

-- | Stream and
-- \"[armor](https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#ascii-armor)\"
-- an age file.
conduitArmor :: Monad m => ConduitT ByteString ByteString (ExceptT ArmorError m) ()
conduitArmor = await >>= \case
  Nothing -> lift (throwError ArmorNoDataError)
  Just x
    | BS.null x ->
        -- An empty 'ByteString' was consumed from upstream, so try again.
        conduitArmor
    | otherwise -> do
        leftover x
        yield (lineBegin <> "\n")
        conduitEncodeBase64
          .| C.chunksOfE 64
          .| C.intersperse "\n"
        yield ("\n" <> lineEnd <> "\n")

-------------------------------------------------------------------------------
-- Decoding
-------------------------------------------------------------------------------

-- | @eol@ rule from
-- [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468.html#section-3).
eolParser :: Parser ()
eolParser = endOfLine <|> void (char8 '\r')

lineBeginParser :: Parser ()
lineBeginParser = do
  void $ string lineBegin
  eolParser

lineEndParser :: Parser ()
lineEndParser = void $ string lineEnd

-- | @4base64char@ rule from
-- [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468.html#section-3).
fourBase64CharParser :: Parser ByteString
fourBase64CharParser = takeNBase64Chars 4

-- | @base64pad@ rule from
-- [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468.html#section-3).
base64PadParser :: Parser Word8
base64PadParser = char8 '='

-- | Parsed base64-encoded line.
data Base64Line
  = -- | Unpadded base64-encoded line of 64 characters.
    Base64FullUnpaddedLine !ByteString
  | -- | Padded base64-encoded line of 64 characters.
    Base64FullPaddedLine !ByteString
  | -- | Base64-encoded line (either padded or unpadded) of less than 64
    -- characters.
    Base64ShortLine !ByteString

-- | @base64fullline@ rule from
-- [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468.html#section-3).
base64FullUnpaddedLineParser :: Parser Base64Line
base64FullUnpaddedLineParser = Base64FullUnpaddedLine <$> (takeNBase64Chars 64 <* eolParser)

-- | Variant of the @strictbase64finl@ rule from
-- [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468.html#section-3) which only
-- parses a base64-encoded and padded line of 64 characters.
base64FullPaddedLineParser :: Parser Base64Line
base64FullPaddedLineParser =  do
  b64Chars <- count 15 fourBase64CharParser
  remainingB64Chars <- remainingB64CharsParser
  eolParser
  pure $ Base64FullPaddedLine (BS.concat b64Chars <> remainingB64Chars)
  where
    remainingB64CharsParser :: Parser ByteString
    remainingB64CharsParser =
      (mappend <$> takeNBase64Chars 3 <*> (BS.singleton <$> base64PadParser))
        <|> (mappend <$> takeNBase64Chars 2 <*> (BS.pack <$> count 2 base64PadParser))

-- | Variant of the @strictbase64finl@ rule from
-- [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468.html#section-3) which only
-- parses a base64-encoded line (either padded or not) that is less than 64
-- characters.
base64ShortLineParser :: Parser Base64Line
base64ShortLineParser = do
  b64Chars <- countMN 0 14 fourBase64CharParser
  remainingB64Chars <-
    if length b64Chars == 0
      then Just <$> remainingB64CharsParser
      else optional remainingB64CharsParser
  eolParser
  pure $ Base64ShortLine (BS.concat b64Chars <> maybe BS.empty id remainingB64Chars)
  where
    remainingB64CharsParser :: Parser ByteString
    remainingB64CharsParser =
      takeNBase64Chars 4
        <|> (mappend <$> takeNBase64Chars 3 <*> (BS.singleton <$> base64PadParser))
        <|> (mappend <$> takeNBase64Chars 2 <*> (BS.pack <$> count 2 base64PadParser))

sinkParseLineBegin :: Monad m => ConduitT ByteString o m (Either ParseError ())
sinkParseLineBegin = sinkParserEither lineBeginParser

-- | Internal helper type for 'conduitParseBase64UntilLineEnd'.
data ParsedLine
  = ParsedLineBase64 !Base64Line
  | ParsedLineEnd

conduitParseBase64UntilLineEnd :: Monad m => ConduitT ByteString ByteString (ExceptT UnarmorError m) ()
conduitParseBase64UntilLineEnd = await >>= \case
  Nothing ->
    -- End of input was reached, but the ending line was not parsed.
    lift (throwError UnarmorNoLineEndError)
  Just x -> do
    leftover x
    res <-
      sinkParserEither $
        (ParsedLineBase64 <$> base64FullUnpaddedLineParser)
          <|> (ParsedLineBase64 <$> base64FullPaddedLineParser)
          <|> (ParsedLineBase64 <$> base64ShortLineParser)
          <|> (lineEndIgnoreWhitespaceParser *> pure ParsedLineEnd)
    case res of
      Left err -> lift (throwError $ UnarmorParseError err)
      Right (ParsedLineBase64 parsedB64Line) ->
        case parsedB64Line of
          Base64FullUnpaddedLine b64Line -> do
            yield b64Line
            conduitParseBase64UntilLineEnd
          Base64FullPaddedLine b64Line -> do
            -- Parsed a padded line, so we should be at the end line now.
            yield b64Line
            lineEndRes <- sinkParserEither lineEndIgnoreWhitespaceParser
            case lineEndRes of
              Left err -> lift (throwError $ UnarmorParseError err)
              Right () -> pure ()
          Base64ShortLine b64Line -> do
            -- Parsed a short line, so we should be at the end line now.
            yield b64Line
            lineEndRes <- sinkParserEither lineEndIgnoreWhitespaceParser
            case lineEndRes of
              Left err -> lift (throwError $ UnarmorParseError err)
              Right () -> pure ()
      Right ParsedLineEnd -> pure ()
  where
    lineEndIgnoreWhitespaceParser :: Parser ()
    lineEndIgnoreWhitespaceParser = lineEndParser >> skipSpace >> endOfInput

-- | Error
-- \"un-[armoring](https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#ascii-armor)\"
-- an age file.
data UnarmorError
  = -- | End of input was reached immediately after parsing the beginning line.
    UnarmorNoDataAfterLineBeginError
  | -- | End of input was reached before the ending line was parsed.
    UnarmorNoLineEndError
  | -- | Error parsing the ASCII-armored age file.
    UnarmorParseError !ParseError
  | -- | Error base64 decoding the encapsulated text portion of the
    -- ASCII-armored age file.
    UnarmorDecodeBase64Error !Text
  deriving stock (Show)

-- | Stream and
-- \"un-[armor](https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#ascii-armor)\"
-- an age file.
conduitUnarmor :: Monad m => ConduitT ByteString ByteString (ExceptT UnarmorError m) ()
conduitUnarmor = do
  -- Ignore leading whitespace
  void (sinkParserEither skipSpace)

  sinkParseLineBegin >>= \case
    Left err -> lift (throwError $ UnarmorParseError err)
    Right () -> pure ()

  -- Ensure that we try to parse at least one more line.
  await >>= \case
    Nothing -> lift (throwError UnarmorNoDataAfterLineBeginError)
    Just x -> do
      leftover x
      conduitParseBase64UntilLineEnd
        .| transPipe (withExceptT UnarmorDecodeBase64Error) conduitDecodeBase64
