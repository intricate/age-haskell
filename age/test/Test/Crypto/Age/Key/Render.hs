module Test.Crypto.Age.Key.Render
  ( unsafeRenderFileKey
  , unsafeRenderPayloadKey
  ) where

import Crypto.Age.Key ( FileKey (..), PayloadKey (..) )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import Prelude

unsafeRenderFileKey :: FileKey -> String
unsafeRenderFileKey (FileKey bs) =
  show (BA.convert bs :: ByteString)

unsafeRenderPayloadKey :: PayloadKey -> String
unsafeRenderPayloadKey (PayloadKey bs) =
  show (BA.convert bs :: ByteString)
