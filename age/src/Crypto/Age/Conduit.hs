{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}

-- | Streaming encryption and decryption of age files.
--
-- TODO: Maybe call this @Crypto.Age.Streaming@?
module Crypto.Age.Conduit
  ( -- * Encryption
    EncryptError (..)
  , EncryptPayloadError (..)
  , conduitEncrypt
  , conduitEncryptEither
  , conduitEncryptEitherPure
  , sinkEncrypt
  , sinkEncryptEither
    -- ** Buffered
  , encryptPayloadChunk
    -- ** Parameters
  , RecipientEncryptionParams (..)
  , mkRecipientEncryptionParams

    -- * Decryption
  , DecryptError (..)
  , DecryptPayloadError (..)
  , DecryptPayloadChunkError (..)
  , conduitDecrypt
  , conduitDecryptEither
  , sinkDecrypt
  , sinkDecryptEither
    -- ** Buffered
  , decryptPayloadChunk
  ) where

import Control.Monad ( when )
import Control.Monad.Except ( ExceptT, throwError )
import Control.Monad.IO.Class ( MonadIO (liftIO) )
import Control.Monad.Trans.Class ( MonadTrans (lift) )
import Crypto.Age.Header
  ( Header (..)
  , HeaderMac
  , Stanza (..)
  , computeHeaderMac
  , headerBuilder
  , headerParser
  )
import Crypto.Age.Identity
  ( Identity, X25519Identity (..), generateX25519Identity )
import Crypto.Age.Identity.Stanza
  ( UnwrapStanzaError, unwrapStanzasWithIdentities )
import Crypto.Age.Key
  ( FileKey
  , PayloadKey
  , PayloadKeyNonce
  , generateFileKey
  , generatePayloadKeyNonce
  , mkPayloadKey
  , payloadKeyNonceBuilder
  , payloadKeyNonceParser
  , payloadKeyToBytes
  )
import Crypto.Age.Payload.Ciphertext
  ( CiphertextPayloadChunk (..)
  , FinalCiphertextPayloadChunk (..)
  , authenticationTagSize
  , ciphertextPayloadChunkParser
  , ciphertextPayloadChunkToBytes
  , mkFinalCiphertextPayloadChunk
  , mkNormalCiphertextPayloadChunk
  )
import Crypto.Age.Payload.Counter
  ( IsFinalChunk (..)
  , PayloadChunkCounter
  , incrementPayloadChunkCounter
  , maxPayloadChunkCounter
  , toChaCha20Poly1305Nonce
  , zeroPayloadChunkCounter
  )
import Crypto.Age.Payload.Plaintext
  ( PlaintextPayloadChunk (..)
  , mkFinalPlaintextPayloadChunk
  , mkNormalPlaintextPayloadChunk
  , plaintextPayloadChunkParser
  , plaintextPayloadChunkToBytes
  )
import Crypto.Age.Recipient
  ( Recipients (..), ScryptRecipient (..), X25519Recipient )
import Crypto.Age.Recipient.Stanza
  ( WrapX25519StanzaFileKeyError
  , fromScryptRecipientStanza
  , fromX25519RecipientStanza
  , scryptStanzaTag
  , wrapFileKeyForScryptRecipient
  , wrapFileKeyForX25519Recipient
  )
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaCha20Poly1305
import qualified Crypto.Error as Crypto
import qualified Crypto.MAC.Poly1305 as Poly1305
import Data.Bifunctor ( bimap, first, second )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as Builder
import Data.Conduit ( ConduitT, await, awaitForever, leftover, yield, (.|) )
import Data.Conduit.Attoparsec
  ( ParseError, conduitParserEither, sinkParserEither )
import qualified Data.Conduit.Combinators as C
import Data.Conduit.Lift ( exceptC )
import Data.Foldable ( find )
import Data.List.NonEmpty ( NonEmpty )
import qualified Data.List.NonEmpty as NE
import Data.Maybe ( fromMaybe, isJust )
import Prelude

-- | Send an incrementing 'PayloadChunkCounter' downstream alongside each
-- upstream value.
--
-- TODO: consider defining this as a source and using 'mergeSource' instead.
--
-- TODO: consider 'throwM'ing an 'Exception' instead of calling 'error' in the
-- event that the counter would exceed 'maxPayloadChunkCounter'.
conduitIncludeCounter :: Monad m => ConduitT i (PayloadChunkCounter, i) m ()
conduitIncludeCounter = await >>= \case
  Nothing -> pure ()
  Just firstVal ->
    C.scanl
     (\(accCounter, _) x -> (fromMaybe err (incrementPayloadChunkCounter accCounter), x))
     (zeroPayloadChunkCounter, firstVal)
  where
    err :: a
    err = error $
      "conduitIncludeCounter: tried to increment counter over "
        <> show maxPayloadChunkCounter

-------------------------------------------------------------------------------
-- Encryption
-------------------------------------------------------------------------------

-- | Parse a plaintext stream of bytes into 64 KiB chunks.
conduitParsePlaintextPayloadChunk ::
  Monad m =>
  ConduitT ByteString (Either ParseError PlaintextPayloadChunk) m ()
conduitParsePlaintextPayloadChunk =
  conduitParserEither plaintextPayloadChunkParser
    .| C.map (second snd)

-- | Encrypt a chunk of an age file
-- [payload](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#payload).
encryptPayloadChunk ::
  -- | Payload key.
  PayloadKey ->
  -- | Payload chunk counter (used in constructing the @ChaCha20-Poly1305@
  -- nonce).
  PayloadChunkCounter ->
  -- | Payload chunk to be encrypted.
  PlaintextPayloadChunk ->
  CiphertextPayloadChunk
encryptPayloadChunk payloadKey counter chunk = do
  let isFinalChunk :: IsFinalChunk
      isFinalChunk =
        case chunk of
          PlaintextPayloadChunkNormal _ -> IsNotFinalChunk
          PlaintextPayloadChunkFinal _ -> IsFinalChunk

      plaintext :: ByteString
      plaintext = plaintextPayloadChunkToBytes chunk

      nonce :: ChaCha20Poly1305.Nonce
      nonce = toChaCha20Poly1305Nonce isFinalChunk counter

      st :: ChaCha20Poly1305.State
      st = Crypto.throwCryptoError $ ChaCha20Poly1305.initialize (payloadKeyToBytes payloadKey) nonce

      ciphertext :: ByteString
      st2 :: ChaCha20Poly1305.State
      (ciphertext, st2) = ChaCha20Poly1305.encrypt plaintext st

      authTag :: Poly1305.Auth
      authTag = ChaCha20Poly1305.finalize st2

      ciphertextAndTag :: ByteString
      ciphertextAndTag = ciphertext <> BA.convert authTag

  case isFinalChunk of
    IsNotFinalChunk ->
      case mkNormalCiphertextPayloadChunk ciphertextAndTag of
        Nothing -> error "impossible: could not construct NormalCiphertextPayloadChunk chunk from encrypted NormalPlaintextPayloadChunk"
        Just c -> CiphertextPayloadChunkNormal c
    IsFinalChunk ->
      case mkFinalCiphertextPayloadChunk ciphertextAndTag of
        Nothing -> error "impossible: could not construct FinalCiphertextPayloadChunk chunk from encrypted FinalPlaintextPayloadChunk"
        Just c -> CiphertextPayloadChunkFinal c

-- | Error encrypting an age file payload.
data EncryptPayloadError
  = -- | Error parsing a plaintext payload chunk.
    EncryptPayloadPlaintextPayloadChunkParseError !ParseError
  deriving stock (Show)

-- | Stream and encrypt an age file
-- [payload](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#payload).
conduitEncryptPayload ::
  Monad m =>
  FileKey ->
  PayloadKeyNonce ->
  ConduitT ByteString (Either EncryptPayloadError ByteString) m ()
conduitEncryptPayload fileKey payloadKeyNonce = do
  let payloadKey :: PayloadKey
      payloadKey = mkPayloadKey payloadKeyNonce fileKey

  -- Push the encoded payload key nonce downstream.
  yield (Right . BS.toStrict . Builder.toLazyByteString $ payloadKeyNonceBuilder payloadKeyNonce)

  -- Consume and encrypt the plaintext.
  --
  -- Ensure that we try to encrypt at least one plaintext chunk. This prevents
  -- us from creating an invalid age file with no ciphertext chunks.
  --
  -- > Streaming decryption MUST signal an error if the end of file is
  -- > reached without successfully decrypting a final chunk.
  --
  -- https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#payload
  await >>= \case
    Nothing ->
      -- There are no upstream values to encrypt, so let's provide an empty
      -- byte string to be encrypted.
      --
      -- That way, we'll create an age file with a single ciphertext payload
      -- chunk.
      yield BS.empty
        .| conduitParseAndEncryptChunk payloadKey
    Just x -> do
      leftover x
      conduitParseAndEncryptChunk payloadKey

  where
    conduitEncryptChunk ::
      Monad m =>
      PayloadKey ->
      ConduitT (PayloadChunkCounter, Either ParseError PlaintextPayloadChunk) (Either EncryptPayloadError CiphertextPayloadChunk) m ()
    conduitEncryptChunk payloadKey = go
      where
        go = await >>= \case
          Nothing -> pure ()
          Just (_, Left err) -> yield (Left $ EncryptPayloadPlaintextPayloadChunkParseError err)
          Just (counter, Right chunk) -> do
            yield (Right $ encryptPayloadChunk payloadKey counter chunk)
            go

    conduitParseAndEncryptChunk ::
      Monad m =>
      PayloadKey ->
      ConduitT ByteString (Either EncryptPayloadError ByteString) m ()
    conduitParseAndEncryptChunk payloadKey =
      conduitParsePlaintextPayloadChunk
        .| conduitIncludeCounter
        .| conduitEncryptChunk payloadKey
        .| C.map (second ciphertextPayloadChunkToBytes)

-- | Recipient-specific encryption parameters.
data RecipientEncryptionParams
  = RecipientEncryptionParamsScrypt !ScryptRecipient
  | RecipientEncryptionParamsX25519 !(NonEmpty (X25519Recipient, X25519Identity))
  deriving stock (Show, Eq)

-- | Construct 'RecipientEncryptionParams' for the provided 'Recipients'.
mkRecipientEncryptionParams :: Recipients -> IO RecipientEncryptionParams
mkRecipientEncryptionParams = \case
  RecipientsScrypt r -> pure (RecipientEncryptionParamsScrypt r)
  RecipientsX25519 rs ->
    RecipientEncryptionParamsX25519
      <$> mapM (\r -> (,) r <$> generateX25519Identity) rs

-- | Error encrypting an age file.
data EncryptError
  = -- | Error wrapping a file key in an X25519 recipient stanza.
    EncryptWrapX25519StanzaFileKeyError !WrapX25519StanzaFileKeyError
  | -- | Error encrypting an age file payload.
    EncryptEncryptPayloadError !EncryptPayloadError
  deriving stock (Show)

-- | Pure variant of 'conduitEncryptEither'.
--
-- For typical usage, please use 'conduitEncryptEither'.
conduitEncryptEitherPure ::
  Monad m =>
  -- | Recipient-specific encryption parameters.
  --
  -- It is recommended to construct this using 'mkRecipientEncryptionParams'.
  RecipientEncryptionParams ->
  -- | Symmetric file key.
  --
  -- It is recommended to generate this from the operating system's CSPRNG
  -- using 'generateFileKey'.
  FileKey ->
  -- | Payload key nonce.
  --
  -- It is recommended to generate this from the operating system's CSPRNG
  -- using 'generatePayloadKeyNonce'.
  PayloadKeyNonce ->
  ConduitT ByteString (Either EncryptError ByteString) m ()
conduitEncryptEitherPure recipientParams fileKey payloadKeyNonce = do
  let stanzasRes :: Either WrapX25519StanzaFileKeyError (NonEmpty Stanza)
      stanzasRes =
        case recipientParams of
          RecipientEncryptionParamsScrypt r ->
            Right . NE.singleton $ fromScryptRecipientStanza (wrapFileKeyForScryptRecipient r fileKey)
          RecipientEncryptionParamsX25519 ris ->
            mapM
              (\(r, i) -> fromX25519RecipientStanza <$> wrapFileKeyForX25519Recipient r i fileKey)
              ris
  case stanzasRes of
    Left err -> yield (Left $ EncryptWrapX25519StanzaFileKeyError err)
    Right stanzas -> do
      let headerMac :: HeaderMac
          headerMac = computeHeaderMac fileKey stanzas

          header :: Header
          header =
            Header
              { hStanzas = stanzas
              , hMac = headerMac
              }

      -- Encode the header and push the bytes downstream
      yield (Right . BS.toStrict . Builder.toLazyByteString $ headerBuilder header)

      -- Consume and encrypt plaintext chunks.
      conduitEncryptPayload fileKey payloadKeyNonce
        .| C.map (first EncryptEncryptPayloadError)

-- | Stream and age encrypt a byte string.
--
-- Errors are returned in the stream. For a variant that only returns errors
-- after the pipeline is run, see 'conduitEncrypt'.
conduitEncryptEither ::
  MonadIO m =>
  Recipients ->
  ConduitT ByteString (Either EncryptError ByteString) m ()
conduitEncryptEither recipients = do
  recipientParams <- liftIO (mkRecipientEncryptionParams recipients)
  fileKey <- liftIO generateFileKey
  payloadKeyNonce <- liftIO generatePayloadKeyNonce
  conduitEncryptEitherPure recipientParams fileKey payloadKeyNonce

-- | Stream and age encrypt a byte string.
--
-- Errors are returned after the pipeline is run. For a variant that includes
-- errors in the stream, see 'conduitEncryptEither'.
conduitEncrypt ::
  MonadIO m =>
  Recipients ->
  ConduitT ByteString ByteString (ExceptT EncryptError m) ()
conduitEncrypt recipients =
  conduitEncryptEither recipients
    .| go
  where
    go ::
      Monad m =>
      ConduitT (Either EncryptError ByteString) ByteString (ExceptT EncryptError m) ()
    go = awaitForever $ \case
      Left err -> lift (throwError err)
      Right bs -> yield bs

-- | Stream and age encrypt a byte string.
--
-- Errors are returned in the stream. For a variant that only returns errors
-- after the pipeline is run, see 'sinkEncrypt'.
sinkEncryptEither ::
  MonadIO m =>
  Recipients ->
  ConduitT ByteString o m (Either EncryptError ByteString)
sinkEncryptEither recipients =
  conduitEncryptEither recipients
    .| go mempty
  where
    go ::
      Monad m =>
      ByteString ->
      ConduitT (Either EncryptError ByteString) o m (Either EncryptError ByteString)
    go !acc = await >>= \case
      Nothing -> pure (Right acc)
      Just (Left err) -> pure (Left err)
      Just (Right bs) -> go (acc <> bs)

-- | Stream and age encrypt a byte string.
--
-- Errors are returned after the pipeline is run. For a variant that includes
-- errors in the stream, see 'sinkEncryptEither'.
sinkEncrypt ::
  MonadIO m =>
  Recipients ->
  ConduitT ByteString o (ExceptT EncryptError m) ByteString
sinkEncrypt recipients = exceptC (sinkEncryptEither recipients)

-------------------------------------------------------------------------------
-- Decryption
-------------------------------------------------------------------------------

-- | Stream and parse an age file 'Header'.
sinkParseHeader :: Monad m => ConduitT ByteString o m (Either ParseError Header)
sinkParseHeader = sinkParserEither headerParser

-- | Stream and parse an age file
-- [payload](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#payload)
-- into 64 KiB chunks of ciphertext.
conduitParseCiphertextPayloadChunk ::
  Monad m =>
  ConduitT ByteString (Either ParseError CiphertextPayloadChunk) m ()
conduitParseCiphertextPayloadChunk =
  conduitParserEither ciphertextPayloadChunkParser
    .| C.map (second snd)

-- | Error decrypting an age file payload chunk.
data DecryptPayloadChunkError
  = -- | Invalid @Poly1305@ authentication tag size.
    DecryptPayloadChunkInvalidAuthenticationTagSizeError !Int
  | -- | Invalid @Poly1305@ authentication tag.
    DecryptPayloadChunkInvalidAuthenticationTagError
      -- | Expected authentication tag.
      !ByteString
      -- | Actual authentication tag.
      !ByteString
  deriving stock (Show, Eq)

-- | Decrypt a chunk of an age file
-- [payload](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#payload).
decryptPayloadChunk ::
  -- | Payload key.
  PayloadKey ->
  -- | Payload chunk counter (used in constructing the @ChaCha20-Poly1305@
  -- nonce).
  PayloadChunkCounter ->
  -- | Payload chunk to be decrypted.
  CiphertextPayloadChunk ->
  Either DecryptPayloadChunkError PlaintextPayloadChunk
decryptPayloadChunk payloadKey counter chunk = do
  let isFinalChunk :: IsFinalChunk
      isFinalChunk =
        case chunk of
          CiphertextPayloadChunkNormal _ -> IsNotFinalChunk
          CiphertextPayloadChunkFinal _ -> IsFinalChunk

      chunkBs :: ByteString
      chunkBs = ciphertextPayloadChunkToBytes chunk

      ciphertext :: ByteString
      ciphertext = BS.dropEnd 16 chunkBs

      actualAuthTagBs :: ByteString
      actualAuthTagBs = BS.takeEnd 16 chunkBs

      actualAuthTagBsLen :: Int
      actualAuthTagBsLen = BS.length actualAuthTagBs

  actualAuthTag <-
    first
      (const $ DecryptPayloadChunkInvalidAuthenticationTagSizeError actualAuthTagBsLen)
      (Crypto.eitherCryptoError $ Poly1305.authTag actualAuthTagBs)

  let nonce = toChaCha20Poly1305Nonce isFinalChunk counter

      st :: ChaCha20Poly1305.State
      st = Crypto.throwCryptoError $ ChaCha20Poly1305.initialize (payloadKeyToBytes payloadKey) nonce

      plaintext :: ByteString
      st2 :: ChaCha20Poly1305.State
      (plaintext, st2) = ChaCha20Poly1305.decrypt ciphertext st

      expectedAuthTag :: Poly1305.Auth
      expectedAuthTag = ChaCha20Poly1305.finalize st2

  when
    (expectedAuthTag /= actualAuthTag)
    (Left $ DecryptPayloadChunkInvalidAuthenticationTagError (BA.convert expectedAuthTag) (BA.convert actualAuthTag))

  case isFinalChunk of
    IsNotFinalChunk ->
      case mkNormalPlaintextPayloadChunk plaintext of
        Nothing -> error "impossible: could not construct NormalPlaintextPayloadChunk chunk from decrypted NormalCiphertextPayloadChunk"
        Just c -> Right (PlaintextPayloadChunkNormal c)
    IsFinalChunk ->
      case mkFinalPlaintextPayloadChunk plaintext of
        Nothing -> error "impossible: could not construct FinalPlaintextPayloadChunk chunk from decrypted FinalCiphertextPayloadChunk"
        Just c -> Right (PlaintextPayloadChunkFinal c)

-- | Error decrypting an age file payload.
data DecryptPayloadError
  = -- | Error parsing the 'PayloadKeyNonce'.
    DecryptPayloadKeyNonceParseError !ParseError
  | -- | Ciphertext payload is null (i.e. end of input was reached without
    -- consuming any ciphertext bytes).
    --
    -- /\"Streaming decryption MUST signal an error if the end of file is reached without successfully decrypting a final chunk.\"/
    --
    -- See the
    -- [age specification](https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#payload)
    -- for more information.
    DecryptPayloadNullPayloadError
  | -- | Error parsing a ciphertext payload chunk.
    DecryptPayloadCiphertextPayloadChunkParseError !ParseError
  | -- | Encountered an empty final ciphertext payload chunk for a non-empty payload.
    --
    -- /\"The final chunk MAY be shorter than 64 KiB but MUST NOT be empty unless the whole payload is empty.\"/
    --
    -- See the
    -- [age specification](https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#payload)
    -- for more information.
    --
    -- Note that \"empty\" here refers to the result of encrypting an empty
    -- byte string with @ChaCha20-Poly1305@. Meaning that this final chunk only
    -- consists of a 16-byte @Poly1305@ authentication tag, but no @ChaCha20@
    -- ciphertext.
    DecryptPayloadNonEmptyPayloadEmptyFinalChunk
  | -- | Error decrypting a payload chunk.
    DecryptPayloadDecryptPayloadChunkError !PayloadChunkCounter !DecryptPayloadChunkError
  deriving stock (Show)

-- | Stream and decrypt an age file
-- [payload](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#payload).
conduitDecryptPayload ::
  Monad m =>
  FileKey ->
  ConduitT ByteString (Either DecryptPayloadError PlaintextPayloadChunk) m ()
conduitDecryptPayload fileKey = do
  payloadKeyNonceRes <-
    first DecryptPayloadKeyNonceParseError
      <$> sinkParserEither payloadKeyNonceParser
  case payloadKeyNonceRes of
    Left err -> yield (Left err)
    Right payloadKeyNonce ->
      -- Ensure that we try to decrypt at least one payload chunk.
      --
      -- > Streaming decryption MUST signal an error if the end of file is
      -- > reached without successfully decrypting a final chunk.
      --
      -- https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#payload
      await >>= \case
        Nothing -> yield (Left DecryptPayloadNullPayloadError)
        Just x -> do
          leftover x
          conduitParseCiphertextPayloadChunk
            .| conduitIncludeCounter
            .| conduitDecryptChunk (mkPayloadKey payloadKeyNonce fileKey)
  where
    conduitDecryptChunk ::
      Monad m =>
      PayloadKey ->
      ConduitT (PayloadChunkCounter, Either ParseError CiphertextPayloadChunk) (Either DecryptPayloadError PlaintextPayloadChunk) m ()
    conduitDecryptChunk payloadKey = go
      where
        go = await >>= \case
          Nothing -> pure ()
          Just (_, Left err) -> yield (Left $ DecryptPayloadCiphertextPayloadChunkParseError err)
          Just (counter, Right (CiphertextPayloadChunkFinal (FinalCiphertextPayloadChunk chunkBs)))
            | BS.length chunkBs == authenticationTagSize && counter /= zeroPayloadChunkCounter ->
              -- Check that the final ciphertext payload chunk is not empty
              -- unless the whole payload is empty.
              --
              -- > The final chunk MAY be shorter than 64 KiB but MUST NOT be
              -- > empty unless the whole payload is empty.
              --
              -- https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#payload
              yield (Left DecryptPayloadNonEmptyPayloadEmptyFinalChunk)
          Just (counter, Right chunk) ->
            case decryptPayloadChunk payloadKey counter chunk of
              Left err -> yield (Left $ DecryptPayloadDecryptPayloadChunkError counter err)
              Right plaintext -> do
                yield (Right plaintext)
                go

-- | Error decrypting an age file.
data DecryptError
  = -- | Error parsing the file header.
    DecryptHeaderParseError !ParseError
  | -- | @scrypt@ recipient stanza is not the only stanza in the file header.
    --
    -- As noted in the
    -- [age specification](https://github.com/C2SP/C2SP/blob/34a9210873230d2acaa4a4c9c5d4d1119b2ee77d/age.md#scrypt-recipient-stanza),
    -- no other stanzas can be specified in the header when there is an
    -- @scrypt@ stanza. This is to uphold an expectation of authentication that
    -- is implicit in password-based encryption.
    DecryptScryptStanzaNotAloneError
  | -- | Error unwrapping a recipient stanza.
    DecryptUnwrapStanzaError !UnwrapStanzaError
  | -- | Error finding any recipient stanza which corresponds to any of the
    -- provided identities.
    DecryptNoMatchingRecipientError
  | -- | Invalid header MAC.
    DecryptInvalidHeaderMacError
      -- | Expected header MAC.
      !HeaderMac
      -- | Actual header MAC.
      !HeaderMac
  | -- | Error decrypting the file payload.
    DecryptDecryptPayloadError !DecryptPayloadError
  deriving stock (Show)

-- | Stream and decrypt an age file.
--
-- Errors are returned in the stream. For a variant that only returns errors
-- after the pipeline is run, see 'conduitDecrypt'.
conduitDecryptEither ::
  Monad m =>
  NonEmpty Identity ->
  ConduitT ByteString (Either DecryptError ByteString) m ()
conduitDecryptEither identities = do
  headerRes <- first DecryptHeaderParseError <$> sinkParseHeader
  case headerRes of
    Left err -> yield (Left err)
    Right Header{hStanzas, hMac}
      | hasScryptStanza hStanzas && (length hStanzas > 1) ->
        -- If it looks like there's an scrypt recipient stanza in the header,
        -- check that it is the /only/ stanza (as described in the age
        -- specification).
        --
        -- > scrypt stanzas MAY NOT be mixed with other scrypt stanzas or
        -- > stanzas of other types
        --
        -- https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#scrypt-recipient-stanza
        yield (Left DecryptScryptStanzaNotAloneError)
      | otherwise ->
        -- Attempt to unwrap the file key from any of the recipient stanzas and
        -- decrypt the payload.
        case unwrapStanzasWithIdentities identities hStanzas of
          Left err -> yield (Left $ DecryptUnwrapStanzaError err)
          Right Nothing -> yield (Left DecryptNoMatchingRecipientError)
          Right (Just fk) -> do
            -- TODO: Using 'computeHeaderMac' here could possibly open us up to
            -- canonicalization issues. We should instead compute the HMAC on
            -- the /actual/ serialized bytes of the parsed header.
            --
            -- The Go implementation of age does the same thing that we do:
            -- https://github.com/FiloSottile/age/blob/3d91014ea095e8d70f7c6c4833f89b53a96e0832/primitives.go#L52-L63
            --
            -- However, the Rust implementation does the right thing:
            -- - https://github.com/str4d/rage/blob/d7c727aef96cc007e142f5b21c0d19210154b3c7/age/src/format.rs#L27-L33
            -- - https://github.com/str4d/rage/blob/d7c727aef96cc007e142f5b21c0d19210154b3c7/age/src/format.rs#L63-L74
            let actualHeaderMac = computeHeaderMac fk hStanzas
            if hMac /= actualHeaderMac
              then yield (Left $ DecryptInvalidHeaderMacError hMac actualHeaderMac)
              else
                conduitDecryptPayload fk
                  .| C.map (bimap DecryptDecryptPayloadError plaintextPayloadChunkToBytes)
  where
    -- Predicate to check if a 'Stanza' /looks like/ it might be an @scrypt@
    -- recipient stanza.
    --
    -- We do this just by checking the first argument of the stanza.
    looksLikeScryptStanza :: Stanza -> Bool
    looksLikeScryptStanza Stanza{sTag} = sTag == scryptStanzaTag

    -- Check whether there is an @scrypt@ recipient stanza in the provided
    -- list.
    --
    -- Note that we don't do a full unwrapping of the recipient stanzas here.
    -- Instead, we use 'looksLikeScryptStanza' to check if any of the stanzas
    -- /look like/ an @scrypt@ recipient stanza.
    hasScryptStanza :: NonEmpty Stanza -> Bool
    hasScryptStanza stanzas = isJust (find looksLikeScryptStanza stanzas)

-- | Stream and decrypt an age file.
--
-- Errors are returned after the pipeline is run. For a variant that includes
-- errors in the stream, see 'conduitDecryptEither'.
conduitDecrypt ::
  Monad m =>
  NonEmpty Identity ->
  ConduitT ByteString ByteString (ExceptT DecryptError m) ()
conduitDecrypt identities =
  conduitDecryptEither identities
    .| go
  where
    go ::
      Monad m =>
      ConduitT (Either DecryptError ByteString) ByteString (ExceptT DecryptError m) ()
    go = awaitForever $ \case
      Left err -> lift (throwError err)
      Right bs -> yield bs

-- | Stream and decrypt an age file to a byte string.
--
-- Errors are returned in the stream. For a variant that only returns errors
-- after the pipeline is run, see 'sinkDecrypt'.
sinkDecryptEither ::
  Monad m =>
  NonEmpty Identity ->
  ConduitT ByteString o m (Either DecryptError ByteString)
sinkDecryptEither identities =
  conduitDecryptEither identities
    .| go mempty
  where
    go ::
      Monad m =>
      ByteString ->
      ConduitT (Either DecryptError ByteString) o m (Either DecryptError ByteString)
    go !acc = await >>= \case
      Nothing -> pure (Right acc)
      Just (Left err) -> pure (Left err)
      Just (Right bs) -> go (acc <> bs)

-- | Stream and decrypt an age file to a byte string.
--
-- Errors are returned after the pipeline is run. For a variant that includes
-- errors in the stream, see 'sinkDecryptEither'.
sinkDecrypt ::
  Monad m =>
  NonEmpty Identity ->
  ConduitT ByteString o (ExceptT DecryptError m) ByteString
sinkDecrypt identities = exceptC (sinkDecryptEither identities)
