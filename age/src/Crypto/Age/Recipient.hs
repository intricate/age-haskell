-- | age file recipients.
module Crypto.Age.Recipient
  ( -- * Recipients
    Recipients (..)
    -- * @scrypt@
  , ScryptRecipient (..)
    -- * X25519
  , X25519Recipient (..)
  , bytesToX25519Recipient
  , x25519RecipientToBytes
  , encodeX25519Recipient
  , DecodeX25519RecipientError (..)
  , decodeX25519Recipient
  ) where

import qualified Codec.Binary.Bech32 as Bech32
import Control.Monad ( when )
import Crypto.Age.Scrypt ( Passphrase, Salt, WorkFactor )
import qualified Crypto.Error as Crypto
import qualified Crypto.PubKey.Curve25519 as Curve25519
import Data.Bifunctor ( first )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import Data.List.NonEmpty ( NonEmpty )
import Data.Text ( Text )
import Prelude

-- | [@scrypt@ recipient](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#the-scrypt-recipient-type).
data ScryptRecipient = ScryptRecipient
  { -- | Passphrase.
    srPassphrase :: !Passphrase
  , -- | Salt.
    srSalt :: !Salt
  , -- | @scrypt@ work factor.
    srWorkFactor :: !WorkFactor
  } deriving stock (Show, Eq)

-- | [X25519 recipient](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#the-x25519-recipient-type).
newtype X25519Recipient = X25519Recipient
  { -- | Recipient's Curve25519 public key.
    unX25519Recipient :: Curve25519.PublicKey
  } deriving stock (Show, Eq)

-- | Construct an 'X25519Recipient' from the raw bytes of a Curve25519 public
-- key.
--
-- If the provided byte string does not have a length of 32 (256 bits),
-- 'Nothing' is returned.
bytesToX25519Recipient :: ByteString -> Maybe X25519Recipient
bytesToX25519Recipient =
  (X25519Recipient <$>)
    . Crypto.maybeCryptoError
    . Curve25519.publicKey

-- | Get the raw Curve25519 public key bytes associated with an
-- 'X25519Recipient'.
x25519RecipientToBytes :: X25519Recipient -> ByteString
x25519RecipientToBytes = BA.convert . unX25519Recipient

x25519RecipientBech32Hrp :: Bech32.HumanReadablePart
x25519RecipientBech32Hrp =
  case Bech32.humanReadablePartFromText "age" of
    Left _ -> error "x25519RecipientBech32Hrp: impossible: \"age\" is an invalid HRP"
    Right hrp -> hrp

-- | Encode an 'X25519Recipient' as
-- [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
encodeX25519Recipient :: X25519Recipient -> Either Bech32.EncodingError Text
encodeX25519Recipient r =
  Bech32.encode
    x25519RecipientBech32Hrp
    (Bech32.dataPartFromBytes $ x25519RecipientToBytes r)

-- | Error decoding an 'X25519Recipient' from Bech32.
data DecodeX25519RecipientError
  = -- | Bech32 decoding error.
    DecodeX25519RecipientBech32DecodingError !Bech32.DecodingError
  | -- | Invalid Bech32 human-readable part.
    DecodeX25519RecipientInvalidHumanReadablePartError
      -- | Expected Bech32 human-readable part.
      !Bech32.HumanReadablePart
      -- | Actual Bech32 human-readable part.
      !Bech32.HumanReadablePart
  | -- | Invalid Bech32 data part.
    DecodeX25519RecipientInvalidDataPartError
  | -- | Invalid Curve25519 secret key size.
    DecodeX25519RecipientInvalidSecretKeySizeError
  deriving stock (Show, Eq)

-- | Decode an 'X25519Recipient' from
-- [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
decodeX25519Recipient :: Text -> Either DecodeX25519RecipientError X25519Recipient
decodeX25519Recipient t = do
  (hrp, dp) <- first DecodeX25519RecipientBech32DecodingError (Bech32.decode t)
  when
    (x25519RecipientBech32Hrp /= hrp)
    (Left $ DecodeX25519RecipientInvalidHumanReadablePartError x25519RecipientBech32Hrp hrp)
  dpBs <-
    case Bech32.dataPartToBytes dp of
      Nothing -> Left DecodeX25519RecipientInvalidDataPartError
      Just bs -> Right bs
  case bytesToX25519Recipient dpBs of
    Nothing -> Left DecodeX25519RecipientInvalidSecretKeySizeError
    Just r -> Right r

-- | Collection of age file recipients.
data Recipients
  = -- | @scrypt@ recipient.
    --
    -- As noted in the
    -- [age specification](https://github.com/C2SP/C2SP/blob/34a9210873230d2acaa4a4c9c5d4d1119b2ee77d/age.md#scrypt-recipient-stanza),
    -- no other stanzas can be specified in the header when there is an
    -- @scrypt@ stanza. This is to uphold an expectation of authentication that
    -- is implicit in password-based encryption.
    --
    -- As a result, only one @scrypt@ recipient can be specified.
    RecipientsScrypt !ScryptRecipient
  | -- | X25519 recipients.
    RecipientsX25519 !(NonEmpty X25519Recipient)
  deriving stock (Show, Eq)
