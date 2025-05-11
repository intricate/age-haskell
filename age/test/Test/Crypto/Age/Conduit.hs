{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Age.Conduit
  ( tests
  ) where

import Crypto.Age.Conduit
  ( RecipientEncryptionParams (..)
  , conduitEncryptPure
  , decryptPayloadChunk
  , encryptPayloadChunk
  , sinkDecrypt
  )
import Crypto.Age.Identity
  ( Identity (..), ScryptIdentity (..), toX25519Recipient )
import Crypto.Age.Recipient ( Recipients (..), ScryptRecipient (..) )
import Crypto.Age.Scrypt ( WorkFactor (..) )
import qualified Data.ByteString as BS
import qualified Data.Conduit as C
import qualified Data.Conduit.List as CL
import qualified Data.List.NonEmpty as NE
import Hedgehog
  ( Gen
  , Property
  , annotateShow
  , checkParallel
  , discover
  , forAll
  , forAllWith
  , property
  , tripping
  , (===)
  )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Crypto.Age.Identity.Gen ( genScryptIdentity, genX25519Identity )
import Test.Crypto.Age.Key.Gen ( genFileKey, genPayloadKey, genPayloadKeyNonce )
import Test.Crypto.Age.Key.Render
  ( unsafeRenderFileKey, unsafeRenderPayloadKey )
import Test.Crypto.Age.Payload.Counter.Gen ( genPayloadChunkCounter )
import Test.Crypto.Age.Payload.Plaintext.Gen ( genPlaintextPayloadChunk )
import Test.Crypto.Age.Recipient.Gen ( genX25519Recipients )
import Test.Crypto.Age.Scrypt.Gen ( genSalt, genWorkFactorInRange )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'encryptPayloadChunk' and 'decryptPayloadChunk' round trip.
prop_roundTrip_encryptDecryptPayloadChunk :: Property
prop_roundTrip_encryptDecryptPayloadChunk = property $ do
  payloadKey <- forAllWith unsafeRenderPayloadKey genPayloadKey
  counter <- forAll genPayloadChunkCounter
  plaintext <- forAll genPlaintextPayloadChunk
  tripping
    plaintext
    (encryptPayloadChunk payloadKey counter)
    (decryptPayloadChunk payloadKey counter)

-- | Test that 'conduitEncryptPure' (pure variant of 'conduitEncrypt') and
-- 'conduitDecrypt' round trip.
prop_roundTrip_conduitEncryptDecrypt :: Property
prop_roundTrip_conduitEncryptDecrypt = property $ do
  (senderId, recipients) <- forAll genSenderIdentityAndRecipients
  recipientParams <- forAll (genRecipientEncryptionParams recipients)
  fileKey <- forAllWith unsafeRenderFileKey genFileKey
  payloadKeyNonce <- forAll genPayloadKeyNonce
  expectedPlaintext <- forAll $ Gen.maybe $ Gen.bytes (Range.constant 0 1024)
  let sourcePlaintext =
        case expectedPlaintext of
          Just bs -> C.yield bs
          Nothing ->
            -- Testing the case where no plaintext is streamed.
            CL.sourceNull

  let ciphertextRes =
        C.runConduitPure $
          sourcePlaintext
            C..| sinkEncryptPure recipientParams fileKey payloadKeyNonce
  annotateShow ciphertextRes
  ciphertext <-
    case ciphertextRes of
      Left err -> fail $ "failed to encrypt plaintext: " <> show err
      Right c -> pure c

  let actualPlaintextRes =
        C.runConduitPure $
          C.yield ciphertext
            C..| sinkDecrypt (NE.singleton senderId)
  actualPlaintext <-
    case actualPlaintextRes of
      Left err -> fail $ "failed to decrypt ciphertext: " <> show err
      Right p -> pure p

  case expectedPlaintext of
    Just bs -> bs === actualPlaintext
    Nothing ->
      -- In the case where we didn't stream any plaintext, we should've still
      -- created a valid age file where an empty byte string was encrypted.
      BS.empty === actualPlaintext
  where
    sinkEncryptPure recipientParams fileKey payloadKeyNonce =
      conduitEncryptPure recipientParams fileKey payloadKeyNonce
        C..| go mempty
      where
        go acc = C.await >>= \case
          Nothing -> pure (Right acc)
          Just (Left err) -> pure (Left err)
          Just (Right bs) -> go (acc <> bs)

------------------------------------------------------------------------------
-- Generators
------------------------------------------------------------------------------

genSenderIdentityAndRecipients :: Gen (Identity, Recipients)
genSenderIdentityAndRecipients =
  Gen.choice
    [ genSenderScryptIdentityAndRecipients
    , genSenderX25519IdentityAndRecipients
    ]
  where
    genSenderScryptIdentityAndRecipients :: Gen (Identity, Recipients)
    genSenderScryptIdentityAndRecipients = do
      identity@ScryptIdentity
        { siPassphrase
        , siMaxWorkFactor = WorkFactor maxWorkFactor
        } <- genScryptIdentity
      salt <- genSalt
      workFactor <- genWorkFactorInRange (Range.constant 1 maxWorkFactor)
      let recipient =
            ScryptRecipient
              { srPassphrase = siPassphrase
              , srSalt = salt
              , srWorkFactor = workFactor
              }
      pure (IdentityScrypt identity, RecipientsScrypt recipient)

    genSenderX25519IdentityAndRecipients :: Gen (Identity, Recipients)
    genSenderX25519IdentityAndRecipients = do
      senderId <- genX25519Identity
      let senderRecip = toX25519Recipient senderId
      moreRecipients <- genX25519Recipients 10
      pure (IdentityX25519 senderId, RecipientsX25519 (NE.singleton senderRecip <> moreRecipients))

genRecipientEncryptionParams :: Recipients -> Gen RecipientEncryptionParams
genRecipientEncryptionParams recipients =
  case recipients of
    RecipientsScrypt r -> pure (RecipientEncryptionParamsScrypt r)
    RecipientsX25519 rs ->
      RecipientEncryptionParamsX25519
        <$> mapM (\r -> (,) r <$> genX25519Identity) rs
