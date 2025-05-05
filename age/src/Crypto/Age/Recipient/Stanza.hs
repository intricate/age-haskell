-- | age recipient stanzas.
module Crypto.Age.Recipient.Stanza
  ( -- * @scrypt@ recipient stanza
    ScryptRecipientStanza (..)
  , wrapFileKeyForScryptRecipient
  , ParseScryptStanzaError (..)
  , toScryptRecipientStanza
  , fromScryptRecipientStanza

    -- * X25519 recipient stanza
  , X25519RecipientStanza (..)
  , WrapX25519StanzaFileKeyError (..)
  , wrapFileKeyForX25519Recipient
  , ParseX25519StanzaError (..)
  , toX25519RecipientStanza
  , fromX25519RecipientStanza
  ) where

import Control.Monad ( unless, when )
import Crypto.Age.Header ( Stanza (..) )
import Crypto.Age.Identity ( X25519Identity (..) )
import Crypto.Age.Key ( FileKey, fileKeyToBytes )
import Crypto.Age.Recipient ( ScryptRecipient (..), X25519Recipient (..) )
import Crypto.Age.Scrypt
  ( Passphrase (..)
  , Salt
  , WorkFactor (..)
  , bytesToSalt
  , saltToBytes
  , workFactorBuilder
  , workFactorParser
  )
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaCha20Poly1305
import qualified Crypto.Error as Crypto
import qualified Crypto.Hash as Crypto
import qualified Crypto.KDF.HKDF as HKDF
import qualified Crypto.KDF.Scrypt as Scrypt
import qualified Crypto.MAC.Poly1305 as Poly1305
import qualified Crypto.PubKey.Curve25519 as Curve25519
import Data.Attoparsec.ByteString ( parseOnly )
import Data.ByteArray ( ScrubbedBytes )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.ByteString.Base64.Extra
  ( decodeBase64StdUnpadded, encodeBase64StdUnpadded )
import qualified Data.ByteString.Builder as Builder
import Data.Text ( Text )
import Prelude

-- | [@scrypt@ recipient stanza](https://github.com/C2SP/C2SP/blob/34a9210873230d2acaa4a4c9c5d4d1119b2ee77d/age.md#scrypt-recipient-stanza).
data ScryptRecipientStanza = ScryptRecipientStanza
  { -- | Salt.
    srsSalt :: !Salt
  , -- | @scrypt@ work factor.
    srsWorkFactor :: !WorkFactor
  , -- | Encrypted file key.
    srsEncryptedFileKey :: !ByteString
  } deriving stock (Show, Eq)

-- | Wrap a 'FileKey' for an 'ScryptRecipient'.
wrapFileKeyForScryptRecipient ::
  ScryptRecipient ->
  FileKey ->
  ScryptRecipientStanza
wrapFileKeyForScryptRecipient r fk = do
  let salt :: ByteString
      salt = "age-encryption.org/v1/scrypt" <> saltToBytes srSalt

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

      ciphertext :: ByteString
      st2 :: ChaCha20Poly1305.State
      (ciphertext, st2) = ChaCha20Poly1305.encrypt (BA.convert $ fileKeyToBytes fk) st

      authTag :: Poly1305.Auth
      authTag = ChaCha20Poly1305.finalize st2

  ScryptRecipientStanza
    { srsSalt = srSalt
    , srsWorkFactor = srWorkFactor
    , srsEncryptedFileKey = ciphertext <> BA.convert authTag
    }
  where
    ScryptRecipient
      { srPassphrase = Passphrase passphrase
      , srSalt
      , srWorkFactor
      } = r

    WorkFactor workFactorW8 = srWorkFactor

scryptStanzaTag :: ByteString
scryptStanzaTag = "scrypt"

-- | Error converting a 'Stanza' to an 'ScryptRecipientStanza'.
data ParseScryptStanzaError
  = -- | Invalid tag.
    ParseScryptStanzaInvalidTagError
      -- | Expected tag.
      !ByteString
      -- | Actual tag.
      !ByteString
  | -- | Invalid number of arguments.
    ParseScryptStanzaInvalidNumberOfArgumentsError
      -- | Expected number of arguments.
      !Int
      -- | Actual number of arguments.
      !Int
  | -- | Error decoding the @scrypt@ salt from base64.
    ParseScryptStanzaSaltBase64DecodingError
      -- | Base64 decoding error.
      !Text
  | -- | Invalid @scrypt@ salt size.
    ParseScryptStanzaInvalidSaltSizeError
      -- | Expected body size in bytes.
      !Int
      -- | Actual body size in bytes.
      !Int
  | -- | Error parsing the @scrypt@ work factor.
    ParseScryptStanzaWorkFactorParseError !String
  | -- | Invalid stanza body size.
    ParseScryptStanzaInvalidBodySizeError
      -- | Expected body size in bytes.
      !Int
      -- | Actual body size in bytes.
      !Int
  deriving stock (Show, Eq)

-- | Convert a 'Stanza' in an 'ScryptRecipientStanza'.
toScryptRecipientStanza :: Stanza -> Either ParseScryptStanzaError ScryptRecipientStanza
toScryptRecipientStanza s = do
  unless (sTag == scryptStanzaTag) $ Left (ParseScryptStanzaInvalidTagError scryptStanzaTag sTag)

  (saltB64, workFactorBs) <-
    case sArgs of
      [arg1, arg2] -> Right (arg1, arg2)
      _ ->
        -- We add 1 because, technically, the tag is a stanza argument too.
        Left $ ParseScryptStanzaInvalidNumberOfArgumentsError 3 (length sArgs + 1)

  salt <-
    case decodeBase64StdUnpadded saltB64 of
      Left err -> Left (ParseScryptStanzaSaltBase64DecodingError err)
      Right bs ->
        case bytesToSalt bs of
          Nothing -> Left (ParseScryptStanzaInvalidSaltSizeError 16 (BS.length bs))
          Just salt -> Right salt

  workFactor <-
    case parseOnly workFactorParser workFactorBs of
      Left err -> Left (ParseScryptStanzaWorkFactorParseError err)
      Right wf -> Right wf

  unless (actualBodyLength == expectedBodyLength) $ Left (ParseScryptStanzaInvalidBodySizeError expectedBodyLength actualBodyLength)

  Right $
    ScryptRecipientStanza
      { srsSalt = salt
      , srsWorkFactor = workFactor
      , srsEncryptedFileKey = sBody
      }
  where
    Stanza
      { sTag
      , sArgs
      , sBody
      } = s

    expectedBodyLength :: Int
    expectedBodyLength = 32

    actualBodyLength :: Int
    actualBodyLength = BS.length sBody

-- | Convert an 'ScryptRecipientStanza' to a 'Stanza'.
fromScryptRecipientStanza :: ScryptRecipientStanza -> Stanza
fromScryptRecipientStanza s =
  Stanza
    { sTag = scryptStanzaTag
    , sArgs =
        [ encodeBase64StdUnpadded (saltToBytes srsSalt)
        , BS.toStrict (Builder.toLazyByteString $ workFactorBuilder srsWorkFactor)
        ]
    , sBody = srsEncryptedFileKey
    }
  where
    ScryptRecipientStanza
      { srsSalt
      , srsWorkFactor
      , srsEncryptedFileKey
      } = s

-- | [X25519 recipient stanza](https://github.com/C2SP/C2SP/blob/34a9210873230d2acaa4a4c9c5d4d1119b2ee77d/age.md#x25519-recipient-stanza).
data X25519RecipientStanza = X25519RecipientStanza
  { -- | Sender's ephemeral Curve25519 public key.
    --
    -- Referred to as the \"ephemeral share\" in the age specification.
    xrsSenderPublicKey :: !Curve25519.PublicKey
  , -- | Encrypted file key.
    xrsEncryptedFileKey :: !ByteString
  } deriving stock (Show, Eq)

-- | Error wrapping a file key in an X25519 recipient stanza.
data WrapX25519StanzaFileKeyError
  = -- | DH shared secret is an all-zero value.
    WrapX25519StanzaFileKeyAllZeroSharedSecretError
  deriving stock (Show, Eq)

-- | Wrap a 'FileKey' in an 'X25519RecipientStanza'.
wrapFileKeyForX25519Recipient ::
  X25519Recipient ->
  X25519Identity ->
  FileKey ->
  Either WrapX25519StanzaFileKeyError X25519RecipientStanza
wrapFileKeyForX25519Recipient (X25519Recipient recipientPk) (X25519Identity senderSk) fk = do
  let senderPk :: Curve25519.PublicKey
      senderPk = Curve25519.toPublic senderSk

      salt :: ByteString
      salt = BA.convert senderPk <> BA.convert recipientPk

      info :: ByteString
      info = "age-encryption.org/v1/X25519"

      zeroSharedSecret :: Curve25519.DhSecret
      zeroSharedSecret = Crypto.throwCryptoError $ Curve25519.dhSecret (BA.replicate 32 0x00 :: ScrubbedBytes)

      sharedSecret :: Curve25519.DhSecret
      sharedSecret = Curve25519.dh recipientPk senderSk

  when (sharedSecret == zeroSharedSecret) (Left WrapX25519StanzaFileKeyAllZeroSharedSecretError)

  let prk :: HKDF.PRK Crypto.SHA256
      prk = HKDF.extract salt sharedSecret

      wrapKey :: ScrubbedBytes
      wrapKey = HKDF.expand prk info 32

      nonce :: ChaCha20Poly1305.Nonce
      nonce = Crypto.throwCryptoError $ ChaCha20Poly1305.nonce12 (BS.replicate 12 0x00)

      st :: ChaCha20Poly1305.State
      st = Crypto.throwCryptoError $ ChaCha20Poly1305.initialize wrapKey nonce

      ciphertext :: ByteString
      st2 :: ChaCha20Poly1305.State
      (ciphertext, st2) = ChaCha20Poly1305.encrypt (BA.convert $ fileKeyToBytes fk) st

      authTag :: Poly1305.Auth
      authTag = ChaCha20Poly1305.finalize st2

  Right $
    X25519RecipientStanza
      { xrsSenderPublicKey = senderPk
      , xrsEncryptedFileKey = ciphertext <> BA.convert authTag
      }

x25519StanzaTag :: ByteString
x25519StanzaTag = "X25519"

-- | Error converting a 'Stanza' to an 'X25519RecipientStanza'.
data ParseX25519StanzaError
  = -- | Invalid tag.
    ParseX25519StanzaInvalidTagError
      -- | Expected tag.
      !ByteString
      -- | Actual tag.
      !ByteString
  | -- | Invalid number of arguments.
    ParseX25519StanzaInvalidNumberOfArgumentsError
      -- | Expected number of arguments.
      !Int
      -- | Actual number of arguments.
      !Int
  | -- | Error decoding the sender's ephemeral public key from base64.
    ParseX25519StanzaEphemeralShareBase64DecodingError
      -- | Base64 decoding error.
      !Text
  | -- | Invalid ephemeral share.
    ParseX25519StanzaInvalidEphemeralShareError
      -- | Error that occurred.
      !Crypto.CryptoError
      -- | Invalid ephemeral share bytes.
      !ByteString
  | -- | Invalid stanza body size.
    ParseX25519StanzaInvalidBodySizeError
      -- | Expected body size in bytes.
      !Int
      -- | Actual body size in bytes.
      !Int
  deriving stock (Show, Eq)

-- | Convert a 'Stanza' to an 'X25519RecipientStanza'.
toX25519RecipientStanza :: Stanza -> Either ParseX25519StanzaError X25519RecipientStanza
toX25519RecipientStanza s = do
  unless (sTag == x25519StanzaTag) $ Left (ParseX25519StanzaInvalidTagError x25519StanzaTag sTag)

  ephemeralShareB64 <-
    case sArgs of
      [arg] -> Right arg
      _ ->
        -- We add 1 because, technically, the tag is a stanza argument too.
        Left $ ParseX25519StanzaInvalidNumberOfArgumentsError 2 (length sArgs + 1)

  ephemeralShareBs <-
    case decodeBase64StdUnpadded ephemeralShareB64 of
      Left err -> Left (ParseX25519StanzaEphemeralShareBase64DecodingError err)
      Right bs -> Right bs

  ephemeralShare <-
    case Curve25519.publicKey ephemeralShareBs of
      Crypto.CryptoFailed err -> Left (ParseX25519StanzaInvalidEphemeralShareError err ephemeralShareBs)
      Crypto.CryptoPassed pk -> Right pk

  unless (actualBodyLength == expectedBodyLength) $ Left (ParseX25519StanzaInvalidBodySizeError expectedBodyLength actualBodyLength)

  Right $
    X25519RecipientStanza
      { xrsSenderPublicKey = ephemeralShare
      , xrsEncryptedFileKey = sBody
      }
  where
    Stanza
      { sTag
      , sArgs
      , sBody
      } = s

    expectedBodyLength :: Int
    expectedBodyLength = 32

    actualBodyLength :: Int
    actualBodyLength = BS.length sBody

-- | Convert an 'X25519RecipientStanza' to a 'Stanza'.
fromX25519RecipientStanza :: X25519RecipientStanza -> Stanza
fromX25519RecipientStanza s =
  Stanza
    { sTag = x25519StanzaTag
    , sArgs = [encodeBase64StdUnpadded (BA.convert ephemeralShare)]
    , sBody = xrsEncryptedFileKey
    }
  where
    X25519RecipientStanza
      { xrsSenderPublicKey = ephemeralShare
      , xrsEncryptedFileKey
      } = s
