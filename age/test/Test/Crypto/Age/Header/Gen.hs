module Test.Crypto.Age.Header.Gen
  ( genStanza
  , genStanzas
  , genHeaderMac
  , genHeader
  ) where

import Crypto.Age.Header ( Header (..), HeaderMac (..), Stanza (..) )
import qualified Crypto.Hash as Crypto
import qualified Crypto.MAC.HMAC as Crypto
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.List.NonEmpty ( NonEmpty )
import qualified Data.List.NonEmpty as NE
import Data.Word ( Word8 )
import Hedgehog ( Gen, Range )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude

genVchar :: Gen Word8
genVchar = Gen.word8 (Range.constant 0x21 0x7E)

genVcharString :: Range Int -> Gen ByteString
genVcharString range = BS.pack <$> Gen.list range genVchar

genStanza :: Gen Stanza
genStanza =
  Stanza
    <$> genVcharString (Range.constant 1 256)
    <*> Gen.list (Range.constant 0 10) (genVcharString (Range.constant 1 256))
    <*> Gen.bytes (Range.constant 0 1024)

genStanzas ::
  -- | Upper bound (inclusive) on number of stanzas to generate.
  Int ->
  Gen (NonEmpty Stanza)
genStanzas x = NE.fromList <$> Gen.list (Range.constant 1 x) genStanza

genHeaderMac :: Gen HeaderMac
genHeaderMac = do
  bs <- Gen.bytes (Range.singleton 32)
  case HeaderMac . Crypto.HMAC <$> Crypto.digestFromByteString bs of
    Nothing -> fail "failed to generate a HeaderMac"
    Just x -> pure x

genHeader :: Gen Header
genHeader =
  Header
    <$> genStanzas 10
    <*> genHeaderMac
