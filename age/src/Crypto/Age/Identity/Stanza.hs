{-# LANGUAGE BangPatterns #-}

-- | Unwrapping file keys from recipient stanzas.
module Crypto.Age.Identity.Stanza
  ( -- * Recipient stanza unwrapping
    UnwrapStanzaError (..)
  , unwrapStanzas
  , unwrapStanzasWithIdentities

  -- ** @scrypt@
  , UnwrapScryptStanzaError (..)
  , unwrapScryptStanza

  -- ** X25519
  , UnwrapX25519StanzaError (..)
  , unwrapX25519Stanza
  ) where

import Control.Monad ( when )
import Crypto.Age.Header ( Stanza (..) )
import Crypto.Age.Identity
  ( Identity (..), ScryptIdentity (..), X25519Identity (..) )
import Crypto.Age.Key ( FileKey, bytesToFileKey )
import Crypto.Age.Recipient.Stanza
  ( ParseScryptStanzaError (..)
  , ParseX25519StanzaError (..)
  , ScryptRecipientStanza (..)
  , X25519RecipientStanza (..)
  , toScryptRecipientStanza
  , toX25519RecipientStanza
  )
import Crypto.Age.Scrypt ( Passphrase (..), WorkFactor (..), saltToBytes )
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaCha20Poly1305
import qualified Crypto.Error as Crypto
import qualified Crypto.Hash as Crypto
import qualified Crypto.KDF.HKDF as HKDF
import qualified Crypto.KDF.Scrypt as Scrypt
import qualified Crypto.MAC.Poly1305 as Poly1305
import qualified Crypto.PubKey.Curve25519 as Curve25519
import Data.Bifunctor ( first )
import Data.ByteArray ( ScrubbedBytes )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.List.NonEmpty ( NonEmpty )
import qualified Data.List.NonEmpty as NE
import Prelude

-- | Error unwrapping a recipient stanza.
data UnwrapStanzaError
  = -- | Error unwrapping an @scrypt@ recipient stanza.
    UnwrapStanzaUnwrapScryptStanzaError !UnwrapScryptStanzaError
  | -- | Error unwrapping a X25519 recipient stanza.
    UnwrapStanzaUnwrapX25519StanzaError !UnwrapX25519StanzaError
  deriving stock (Show, Eq)

-- | Attempt to unwrap any of the provided stanzas.
--
-- Note that if there isn't a recipient stanza which corresponds to the
-- provided identity, 'Right' 'Nothing' will be returned.
unwrapStanzas ::
  Identity ->
  NonEmpty Stanza ->
  Either UnwrapStanzaError (Maybe FileKey)
unwrapStanzas identity stanzas = go (Right Nothing) (NE.toList stanzas)
  where
    unwrap :: Stanza -> Either UnwrapStanzaError (Maybe FileKey)
    unwrap s =
      case identity of
        IdentityScrypt i ->
          case unwrapScryptStanza i s of
            Left (UnwrapScryptStanzaParseScryptStanzaError (ParseScryptStanzaInvalidTagError _ _)) ->
              -- This is not an @scrypt@ recipient stanza.
              Right Nothing
            Left (UnwrapScryptStanzaWorkFactorExceedsMaximumError _ _) ->
              -- The recipient's work factor exceeding the identity's
              -- configured maximum is not a fatal error.
              Right Nothing
            Left (UnwrapScryptStanzaInvalidAuthenticationTagError _ _) ->
              -- Failure to verify the authentication tag is not a fatal error.
              --
              -- This error essentially just indicates that decryption has
              -- failed because this stanza is not intended for this identity.
              Right Nothing
            Left err -> Left (UnwrapStanzaUnwrapScryptStanzaError err)
            Right fk -> Right (Just fk)
        IdentityX25519 i ->
          case unwrapX25519Stanza i s of
            Left (UnwrapX25519StanzaParseX25519StanzaError (ParseX25519StanzaInvalidTagError _ _)) ->
              -- This is not a X25519 recipient stanza.
              Right Nothing
            Left (UnwrapX25519StanzaInvalidAuthenticationTagError _ _) ->
              -- Failure to verify the authentication tag is not a fatal error.
              --
              -- This error essentially just indicates that decryption has
              -- failed because this stanza is not intended for this identity.
              Right Nothing
            Left err -> Left (UnwrapStanzaUnwrapX25519StanzaError err)
            Right fk -> Right (Just fk)

    go ::
      Either UnwrapStanzaError (Maybe FileKey) ->
      [Stanza] ->
      Either UnwrapStanzaError (Maybe FileKey)
    go (Right Nothing) (s : ss) = go (unwrap s) ss
    go !acc _ = acc

-- | Attempt to unwrap any of the provided stanzas using any of the provided
-- identities.
--
-- Note that if there isn't a recipient stanza which corresponds to any of the
-- provided identities, 'Right' 'Nothing' will be returned.
unwrapStanzasWithIdentities ::
  NonEmpty Identity ->
  NonEmpty Stanza ->
  Either UnwrapStanzaError (Maybe FileKey)
unwrapStanzasWithIdentities identities stanzas = go (Right Nothing) (NE.toList identities)
  where
    go ::
      Either UnwrapStanzaError (Maybe FileKey) ->
      [Identity] ->
      Either UnwrapStanzaError (Maybe FileKey)
    go (Right Nothing) (i : is) = go (unwrapStanzas i stanzas) is
    go !acc _ = acc

-- | Error unwrapping an @scrypt@ recipient stanza.
data UnwrapScryptStanzaError
  = -- | 'ParseScryptStanzaError' that occurred during unwrapping.
    UnwrapScryptStanzaParseScryptStanzaError !ParseScryptStanzaError
  | -- | Recipient's work factor exceeds the identity's maximum work factor.
    UnwrapScryptStanzaWorkFactorExceedsMaximumError
      -- | Identity's maximum work factor.
      !WorkFactor
      -- | Recipient's work factor.
      !WorkFactor
  | -- | Invalid ciphertext size.
    UnwrapScryptStanzaInvalidCiphertextSizeError !Int
  | -- | Invalid @Poly1305@ authentication tag size.
    UnwrapScryptStanzaInvalidAuthenticationTagSizeError !Int
  | -- | Invalid @Poly1305@ authentication tag.
    UnwrapScryptStanzaInvalidAuthenticationTagError
      -- | Expected authentication tag.
      !ByteString
      -- | Actual authentication tag.
      !ByteString
  | -- | Decrypted file key is invalid.
    UnwrapScryptStanzaInvalidFileKeyError
  deriving stock (Show, Eq)

-- | Attempt to unwrap a 'Stanza' using a 'ScryptIdentity'.
unwrapScryptStanza ::
  ScryptIdentity ->
  Stanza ->
  Either UnwrapScryptStanzaError FileKey
unwrapScryptStanza i s = do
  ScryptRecipientStanza
    { srsSalt
    , srsWorkFactor
    , srsEncryptedFileKey
    } <- first UnwrapScryptStanzaParseScryptStanzaError (toScryptRecipientStanza s)

  let WorkFactor workFactorW8 = srsWorkFactor

  when (workFactorW8 > maxWorkFactorW8) (Left $ UnwrapScryptStanzaWorkFactorExceedsMaximumError siMaxWorkFactor srsWorkFactor)

  let ciphertext :: ByteString
      actualAuthTagBs :: ByteString
      (ciphertext, actualAuthTagBs) = BS.splitAt 16 srsEncryptedFileKey

      ciphertextLen :: Int
      ciphertextLen = BS.length ciphertext

      actualAuthTagBsLen :: Int
      actualAuthTagBsLen = BS.length actualAuthTagBs

  when (ciphertextLen /= 16) (Left $ UnwrapScryptStanzaInvalidCiphertextSizeError ciphertextLen)

  actualAuthTag <-
    first
      (const $ UnwrapScryptStanzaInvalidAuthenticationTagSizeError actualAuthTagBsLen)
      (Crypto.eitherCryptoError $ Poly1305.authTag actualAuthTagBs)

  let salt :: ByteString
      salt = "age-encryption.org/v1/scrypt" <> saltToBytes srsSalt

      params :: Scrypt.Parameters
      params =
        Scrypt.Parameters
          { Scrypt.n = 2 ^ workFactorW8
          , Scrypt.r = 8
          , Scrypt.p = 1
          , Scrypt.outputLength = 32
          }

      wrapKey :: ScrubbedBytes
      wrapKey = Scrypt.generate params passphrase salt

      nonce :: ChaCha20Poly1305.Nonce
      nonce = Crypto.throwCryptoError $ ChaCha20Poly1305.nonce12 (BS.replicate 12 0x00)

      st :: ChaCha20Poly1305.State
      st = Crypto.throwCryptoError $ ChaCha20Poly1305.initialize wrapKey nonce

      plaintext :: ScrubbedBytes
      st2 :: ChaCha20Poly1305.State
      (plaintext, st2) = ChaCha20Poly1305.decrypt (BA.convert ciphertext) st

      expectedAuthTag :: Poly1305.Auth
      expectedAuthTag = ChaCha20Poly1305.finalize st2

  when
    (expectedAuthTag /= actualAuthTag)
    (Left $ UnwrapScryptStanzaInvalidAuthenticationTagError (BA.convert expectedAuthTag) (BA.convert actualAuthTag))

  case bytesToFileKey plaintext of
    Nothing -> Left UnwrapScryptStanzaInvalidFileKeyError
    Just fk -> Right fk
  where
    ScryptIdentity
      { siPassphrase = Passphrase passphrase
      , siMaxWorkFactor
      } = i

    WorkFactor maxWorkFactorW8 = siMaxWorkFactor

-- | Error unwrapping a X25519 recipient stanza.
data UnwrapX25519StanzaError
  = -- | 'ParseX25519StanzaError' that occurred during unwrapping.
    UnwrapX25519StanzaParseX25519StanzaError !ParseX25519StanzaError
  | -- | Invalid ciphertext size.
    UnwrapX25519StanzaInvalidCiphertextSizeError !Int
  | -- | Invalid @Poly1305@ authentication tag size.
    UnwrapX25519StanzaInvalidAuthenticationTagSizeError !Int
  | -- | Computed DH shared secret is an all-zero value.
    UnwrapX25519StanzaAllZeroSharedSecretError
  | -- | Invalid @Poly1305@ authentication tag.
    UnwrapX25519StanzaInvalidAuthenticationTagError
      -- | Expected authentication tag.
      !ScrubbedBytes
      -- | Actual authentication tag.
      !ScrubbedBytes
  | -- | Decrypted file key is invalid.
    UnwrapX25519StanzaInvalidFileKeyError
  deriving stock (Show, Eq)

-- | Attempt to unwrap a 'Stanza' using a 'X25519Identity'.
unwrapX25519Stanza :: X25519Identity -> Stanza -> Either UnwrapX25519StanzaError FileKey
unwrapX25519Stanza (X25519Identity sk) s = do
  X25519RecipientStanza
    { xrsSenderPublicKey = ephemeralShare
    , xrsEncryptedFileKey
    } <- first UnwrapX25519StanzaParseX25519StanzaError (toX25519RecipientStanza s)

  let ciphertext :: ByteString
      actualAuthTagBs :: ByteString
      (ciphertext, actualAuthTagBs) = BS.splitAt 16 xrsEncryptedFileKey

      ciphertextLen :: Int
      ciphertextLen = BS.length ciphertext

      actualAuthTagBsLen :: Int
      actualAuthTagBsLen = BS.length actualAuthTagBs

  when (ciphertextLen /= 16) (Left $ UnwrapX25519StanzaInvalidCiphertextSizeError ciphertextLen)

  actualAuthTag <-
    first
      (const $ UnwrapX25519StanzaInvalidAuthenticationTagSizeError actualAuthTagBsLen)
      (Crypto.eitherCryptoError $ Poly1305.authTag actualAuthTagBs)

  let salt :: ByteString
      salt = BA.convert ephemeralShare <> BA.convert (Curve25519.toPublic sk)

      info :: ByteString
      info = "age-encryption.org/v1/X25519"

      zeroSharedSecret :: Curve25519.DhSecret
      zeroSharedSecret = Crypto.throwCryptoError $ Curve25519.dhSecret (BA.replicate 32 0x00 :: ScrubbedBytes)

      sharedSecret :: Curve25519.DhSecret
      sharedSecret = Curve25519.dh ephemeralShare sk

  when (sharedSecret == zeroSharedSecret) (Left UnwrapX25519StanzaAllZeroSharedSecretError)

  let prk :: HKDF.PRK Crypto.SHA256
      prk = HKDF.extract salt sharedSecret

      wrapKey :: ScrubbedBytes
      wrapKey = HKDF.expand prk info 32

      nonce :: ChaCha20Poly1305.Nonce
      nonce = Crypto.throwCryptoError $ ChaCha20Poly1305.nonce12 (BS.replicate 12 0x00)

      st :: ChaCha20Poly1305.State
      st = Crypto.throwCryptoError $ ChaCha20Poly1305.initialize wrapKey nonce

      plaintext :: ScrubbedBytes
      st2 :: ChaCha20Poly1305.State
      (plaintext, st2) = ChaCha20Poly1305.decrypt (BA.convert ciphertext) st

      expectedAuthTag :: Poly1305.Auth
      expectedAuthTag = ChaCha20Poly1305.finalize st2

  when
    (expectedAuthTag /= actualAuthTag)
    (Left $ UnwrapX25519StanzaInvalidAuthenticationTagError (BA.convert expectedAuthTag) (BA.convert actualAuthTag))

  case bytesToFileKey plaintext of
    Nothing -> Left UnwrapX25519StanzaInvalidFileKeyError
    Just fk -> Right fk
