module Test.Golden
  ( goldenTestWithEncoderAndDecoder
  ) where

import Control.Monad.IO.Class ( liftIO )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import GHC.Stack ( HasCallStack, withFrozenCallStack )
import Hedgehog ( Property, property, withTests, (===) )
import Prelude

-- | Construct a golden test given a binary encoder and decoder.
goldenTestWithEncoderAndDecoder ::
  (HasCallStack, Applicative f, Show (f a), Eq (f a)) =>
  -- | Encoder.
  (a -> ByteString) ->
  -- | Decoder.
  (ByteString -> f a) ->
  -- | Golden value.
  a ->
  -- | Golden file path.
  FilePath ->
  Property
goldenTestWithEncoderAndDecoder encode decode x path = withFrozenCallStack $ withTests 1 . property $ do
  bs <- liftIO (BS.readFile path)
  encode x === bs
  pure x === decode bs
