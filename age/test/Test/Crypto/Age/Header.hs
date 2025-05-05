{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Age.Header
  ( tests
  ) where

import Crypto.Age.Header
  ( Header (..)
  , HeaderMac (..)
  , Stanza (..)
  , headerBuilder
  , headerMacBuilder
  , headerMacParser
  , headerParser
  , stanzaBuilder
  , stanzaParser
  )
import qualified Crypto.Hash as Crypto
import qualified Crypto.MAC.HMAC as Crypto
import Data.Attoparsec.ByteString ( parseOnly )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.ByteString.Builder ( Builder, toLazyByteString )
import qualified Data.List.NonEmpty as NE
import Hedgehog
  ( Property, checkParallel, discover, forAll, property, tripping )
import Prelude
import Test.Crypto.Age.Header.Gen ( genHeader, genHeaderMac, genStanza )
import Test.Golden ( goldenTestWithEncoderAndDecoder )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'stanzaBuilder' and 'stanzaParser' round trip.
prop_roundTrip_encodeParseStanza :: Property
prop_roundTrip_encodeParseStanza = property $ do
  stanza <- forAll genStanza
  tripping
    stanza
    (toStrictByteString . stanzaBuilder)
    (parseOnly stanzaParser)

-- | Test that 'headerMacBuilder' and 'headerMacParser' round trip.
prop_roundTrip_encodeParseHeaderMac :: Property
prop_roundTrip_encodeParseHeaderMac = property $ do
  headerMac <- forAll genHeaderMac
  tripping
    headerMac
    (toStrictByteString . headerMacBuilder)
    (parseOnly headerMacParser)

-- | Test that 'headerBuilder' and 'headerParser' round trip.
prop_roundTrip_encodeParseHeader :: Property
prop_roundTrip_encodeParseHeader = property $ do
  header <- forAll genHeader
  tripping
    header
    (toStrictByteString . headerBuilder)
    (parseOnly headerParser)

prop_golden_stanza :: Property
prop_golden_stanza =
  goldenTestWithEncoderAndDecoder
    (toStrictByteString . stanzaBuilder)
    (parseOnly stanzaParser)
    goldenStanza
    "test/golden/binary/stanza/golden.bin"

prop_golden_headerMac :: Property
prop_golden_headerMac =
  goldenTestWithEncoderAndDecoder
    (toStrictByteString . headerMacBuilder)
    (parseOnly headerMacParser)
    goldenHeaderMac
    "test/golden/binary/header-mac/golden.bin"

prop_golden_header :: Property
prop_golden_header =
  goldenTestWithEncoderAndDecoder
    (toStrictByteString . headerBuilder)
    (parseOnly headerParser)
    goldenHeader
    "test/golden/binary/header/golden.bin"

------------------------------------------------------------------------------
-- Golden examples
------------------------------------------------------------------------------

goldenStanza :: Stanza
goldenStanza =
  Stanza
    { sTag = "tag"
    , sArgs = ["arg1", "arg2", "arg3", "aaaaaaaaaaaaaaaaaa"]
    , sBody = BS.replicate 1024 0x41
    }

goldenHeaderMac :: HeaderMac
goldenHeaderMac =
  case Crypto.digestFromByteString (BS.replicate 32 0x41) of
    Nothing -> error "goldenHeaderMac: impossible: could not construct HMAC"
    Just digest -> HeaderMac (Crypto.HMAC digest)

goldenHeader :: Header
goldenHeader =
  Header
    { hStanzas = goldenStanza NE.:| replicate 10 goldenStanza
    , hMac = goldenHeaderMac
    }

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

toStrictByteString :: Builder -> ByteString
toStrictByteString = BS.toStrict . toLazyByteString
