module Test.Crypto.Age.Recipient.Gen
  ( genScryptRecipient
  , genX25519Recipient
  , genX25519Recipients
  , genRecipients
  ) where

import Crypto.Age.Recipient
  ( Recipients (..), ScryptRecipient (..), X25519Recipient (..) )
import qualified Crypto.Error as Crypto
import qualified Crypto.PubKey.Curve25519 as Crypto
import Data.List.NonEmpty ( NonEmpty )
import qualified Data.List.NonEmpty as NE
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Crypto.Age.Scrypt.Gen ( genPassphrase, genSalt, genWorkFactor )

genScryptRecipient :: Gen ScryptRecipient
genScryptRecipient =
  ScryptRecipient
    <$> genPassphrase
    <*> genSalt
    <*> genWorkFactor

genX25519Recipient :: Gen X25519Recipient
genX25519Recipient = do
  bs <- Gen.bytes (Range.singleton 32)
  case Crypto.eitherCryptoError (Crypto.publicKey bs) of
    Left err -> fail $ "failed to generate a X25519Recipient: " <> show err
    Right x -> pure $ X25519Recipient x

genX25519Recipients ::
  -- | Upper bound (inclusive) on number of recipients to generate.
  Int ->
  Gen (NonEmpty X25519Recipient)
genX25519Recipients x = NE.fromList <$> Gen.list (Range.constant 1 x) genX25519Recipient

genRecipients :: Gen Recipients
genRecipients =
  Gen.choice
    [ RecipientsScrypt <$> genScryptRecipient
    , RecipientsX25519 <$> genX25519Recipients 10
    ]
