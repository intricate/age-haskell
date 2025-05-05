module Data.ByteString.Extra
  ( chunksOf
  ) where

import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Prelude

chunksOf :: Int -> ByteString -> [ByteString]
chunksOf k = go
  where
    go t =
      case BS.splitAt k t of
        (a, b)
          | BS.null a -> []
          | otherwise -> a : go b
