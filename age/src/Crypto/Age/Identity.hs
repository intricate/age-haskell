module Crypto.Age.Identity
  ( -- * Identity
    Identity (..)

    -- ** @scrypt@
  , ScryptIdentity (..)

    -- ** X25519
  , X25519Identity (..)
  , bytesToX25519Identity
  , x25519IdentityToBytes
  , toX25519Recipient
  , generateX25519Identity
  , encodeX25519Identity
  , DecodeX25519IdentityError (..)
  , decodeX25519Identity
  ) where

import qualified Codec.Binary.Bech32 as Bech32
import Control.Monad ( when )
import Crypto.Age.Recipient ( X25519Recipient (..) )
import Crypto.Age.Scrypt ( Passphrase, WorkFactor )
import qualified Crypto.Error as Crypto
import qualified Crypto.PubKey.Curve25519 as Curve25519
import Data.Bifunctor ( first )
import Data.ByteArray ( ScrubbedBytes )
import qualified Data.ByteArray as BA
import Data.Text ( Text )
import Prelude

-- | [@scrypt@ identity](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#the-scrypt-recipient-type).
data ScryptIdentity = ScryptIdentity
  { -- | Passphrase.
    siPassphrase :: !Passphrase
  , -- | Maximum work factor permitted for this identity.
    siMaxWorkFactor :: !WorkFactor
  } deriving stock (Show, Eq)

-- | [X25519 identity](https://github.com/C2SP/C2SP/blob/91935d7157cb3860351ffebbad1e6f6153e8efc8/age.md#the-x25519-recipient-type).
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
newtype X25519Identity = X25519Identity
  { unX25519Identity :: Curve25519.SecretKey }
  deriving newtype (Show, Eq)

-- | Construct an 'X25519Identity' from the raw bytes of a Curve25519 secret
-- key.
--
-- If the provided byte string does not have a length of 32 (256 bits),
-- 'Nothing' is returned.
bytesToX25519Identity :: ScrubbedBytes -> Maybe X25519Identity
bytesToX25519Identity =
  (X25519Identity <$>)
    . Crypto.maybeCryptoError
    . Curve25519.secretKey

-- | Get the raw Curve25519 secret key bytes associated with an
-- 'X25519Identity'.
x25519IdentityToBytes :: X25519Identity -> ScrubbedBytes
x25519IdentityToBytes = BA.convert . unX25519Identity

-- | Get the 'X25519Recipient' which corresponds to the given 'X25519Identity'.
toX25519Recipient :: X25519Identity -> X25519Recipient
toX25519Recipient (X25519Identity sk) =
  X25519Recipient (Curve25519.toPublic sk)

-- | Randomly generate a 'X25519Identity'.
generateX25519Identity :: IO X25519Identity
generateX25519Identity = X25519Identity <$> Curve25519.generateSecretKey

x25519IdentityBech32Hrp :: Bech32.HumanReadablePart
x25519IdentityBech32Hrp =
  case Bech32.humanReadablePartFromText "AGE-SECRET-KEY-" of
    Left _ -> error "x25519IdentityBech32Hrp: impossible: \"AGE-SECRET-KEY-\" is an invalid HRP"
    Right hrp -> hrp

-- | Encode an 'X25519Identity' as
-- [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
encodeX25519Identity :: X25519Identity -> Either Bech32.EncodingError Text
encodeX25519Identity i =
  Bech32.encode
    x25519IdentityBech32Hrp
    (Bech32.dataPartFromBytes . BA.convert $ x25519IdentityToBytes i)

-- | Error decoding an 'X25519Identity' from Bech32.
data DecodeX25519IdentityError
  = -- | Bech32 decoding error.
    DecodeX25519IdentityBech32DecodingError !Bech32.DecodingError
  | -- | Invalid Bech32 human-readable part.
    DecodeX25519IdentityInvalidHumanReadablePartError
      -- | Expected Bech32 human-readable part.
      !Bech32.HumanReadablePart
      -- | Actual Bech32 human-readable part.
      !Bech32.HumanReadablePart
  | -- | Invalid Bech32 data part.
    DecodeX25519IdentityInvalidDataPartError
  | -- | Invalid Curve25519 secret key size.
    DecodeX25519IdentityInvalidSecretKeySizeError
  deriving stock (Show, Eq)

-- | Decode an 'X25519Identity' from
-- [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
decodeX25519Identity :: Text -> Either DecodeX25519IdentityError X25519Identity
decodeX25519Identity t = do
  (hrp, dp) <- first DecodeX25519IdentityBech32DecodingError (Bech32.decode t)
  when
    (x25519IdentityBech32Hrp /= hrp)
    (Left $ DecodeX25519IdentityInvalidHumanReadablePartError x25519IdentityBech32Hrp hrp)
  dpBs <-
    case Bech32.dataPartToBytes dp of
      Nothing -> Left DecodeX25519IdentityInvalidDataPartError
      Just bs -> Right bs
  case bytesToX25519Identity (BA.convert dpBs) of
    Nothing -> Left DecodeX25519IdentityInvalidSecretKeySizeError
    Just i -> Right i

-- | age identity.
data Identity
  = -- | @scrypt@ identity.
    IdentityScrypt !ScryptIdentity
  | -- | X25519 identity.
    IdentityX25519 !X25519Identity
  deriving stock (Show, Eq)
