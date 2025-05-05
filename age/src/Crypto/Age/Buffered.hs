{-# LANGUAGE LambdaCase #-}

-- | Buffered encryption and decryption of age files.
--
-- TODO: maybe call this @Crypto.Age.Simple@?
module Crypto.Age.Buffered
  ( -- * Encryption
    encrypt
  , encryptLazy

    -- * Decryption
  , decrypt
  , decryptLazy
  ) where

import Control.Monad.Except ( ExceptT (..) )
import Crypto.Age.Conduit
  ( DecryptError
  , EncryptError
  , conduitDecrypt
  , conduitEncrypt
  , sinkDecrypt
  , sinkEncrypt
  )
import Crypto.Age.Identity ( Identity )
import Crypto.Age.Recipient ( Recipients )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Conduit ( ConduitT, await, runConduit, runConduitPure, yield, (.|) )
import qualified Data.Conduit.Combinators as C
import Data.List.NonEmpty ( NonEmpty )
import Data.Sequences ( LazySequence )
import Prelude

-------------------------------------------------------------------------------
-- Encryption
-------------------------------------------------------------------------------

-- | Encrypt a strict 'BS.ByteString'.
encrypt :: Recipients -> BS.ByteString -> ExceptT EncryptError IO BS.ByteString
encrypt recipients plaintext =
  ExceptT . runConduit $
    yield plaintext .| sinkEncrypt recipients

-- | Encrypt a lazy 'LBS.ByteString'.
encryptLazy :: Recipients -> LBS.ByteString -> ExceptT EncryptError IO LBS.ByteString
encryptLazy recipients plaintext =
  ExceptT . runConduit $
    C.sourceLazy plaintext .| conduitEncrypt recipients .| sinkLazyEither

-------------------------------------------------------------------------------
-- Decryption
-------------------------------------------------------------------------------

-- | Decrypt a strict 'BS.ByteString'.
decrypt :: NonEmpty Identity -> BS.ByteString -> Either DecryptError BS.ByteString
decrypt identities ciphertext = runConduitPure $ yield ciphertext .| sinkDecrypt identities

-- | Decrypt a lazy 'LBS.ByteString'.
decryptLazy :: NonEmpty Identity -> LBS.ByteString -> Either DecryptError LBS.ByteString
decryptLazy identities ciphertext =
  runConduitPure $
    C.sourceLazy ciphertext .| conduitDecrypt identities .| sinkLazyEither

-------------------------------------------------------------------------------
-- Helpers
-------------------------------------------------------------------------------

sinkLazyEither ::
  (Monad m, LazySequence lazy strict) =>
  ConduitT (Either err strict) o m (Either err lazy)
sinkLazyEither = go mempty
  where
    go acc = await >>= \case
      Nothing -> pure (Right acc)
      Just (Left err) -> pure (Left err)
      Just (Right bs) -> do
        lbs <- yield bs .| C.sinkLazy
        go (acc <> lbs)
