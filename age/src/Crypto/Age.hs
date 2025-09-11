-- | This module is the recommended entry point for this library.
module Crypto.Age
  ( -- * Encryption
    -- ** Buffered
    encrypt
  , encryptLazy
    -- ** Streaming
  , conduitEncrypt
  , sinkEncrypt
    -- ** Errors
  , EncryptError (..)

    -- * Decryption
    -- ** Buffered
  , decrypt
  , decryptLazy
    -- ** Streaming
  , conduitDecrypt
  , conduitDecryptEither
  , sinkDecrypt
  , sinkDecryptEither
    -- ** Errors
  , DecryptError (..)

    -- * Identity
  , Identity (..)
    -- ** @scrypt@
  , ScryptIdentity (..)
    -- ** X25519
  , X25519Identity (..)
    -- *** Construction
  , generateX25519Identity
  , toX25519Recipient
    -- *** Encoding
  , bytesToX25519Identity
  , x25519IdentityToBytes
  , encodeX25519Identity
  , decodeX25519Identity
  , DecodeX25519IdentityError (..)

    -- * Recipient
  , Recipients (..)
    -- ** @scrypt@
  , ScryptRecipient (..)
    -- ** X25519
  , X25519Recipient (..)
  , bytesToX25519Recipient
  , x25519RecipientToBytes
  , encodeX25519Recipient
  , decodeX25519Recipient
  , DecodeX25519RecipientError (..)
  ) where

import Crypto.Age.Buffered ( decrypt, decryptLazy, encrypt, encryptLazy )
import Crypto.Age.Conduit
  ( DecryptError (..)
  , EncryptError (..)
  , conduitDecrypt
  , conduitDecryptEither
  , conduitEncrypt
  , sinkDecrypt
  , sinkDecryptEither
  , sinkEncrypt
  )
import Crypto.Age.Identity
  ( DecodeX25519IdentityError (..)
  , Identity (..)
  , ScryptIdentity (..)
  , X25519Identity (..)
  , bytesToX25519Identity
  , decodeX25519Identity
  , encodeX25519Identity
  , generateX25519Identity
  , toX25519Recipient
  , x25519IdentityToBytes
  )
import Crypto.Age.Recipient
  ( DecodeX25519RecipientError (..)
  , Recipients (..)
  , ScryptRecipient (..)
  , X25519Recipient (..)
  , bytesToX25519Recipient
  , decodeX25519Recipient
  , encodeX25519Recipient
  , x25519RecipientToBytes
  )
