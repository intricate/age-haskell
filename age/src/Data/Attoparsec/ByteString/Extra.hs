module Data.Attoparsec.ByteString.Extra
  ( takeWhileMN
  ) where

import Data.Attoparsec.ByteString ( Parser, scan )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.Word ( Word8 )
import Prelude

-- | Consume the longest (@m <= len <= n@) input slice where the predicate
-- returns 'True', and return the consumed input.
--
-- This parser fails in the event that the length of its consumed input does
-- not satisfy @m <= len <= n@.
takeWhileMN ::
  -- | @m@.
  Word ->
  -- | @n@.
  Word ->
  -- | Predicate.
  (Word8 -> Bool) ->
  Parser ByteString
takeWhileMN m n f
  | m > n = fail "takeWhileMN: m cannot be greater than n"
  | otherwise = do
      bs <- scan 0 transformState
      let len = BS.length bs
      if mI <= len && nI >= len
        then pure bs
        else
          fail $
            "takeWhileMN: consumed input length ("
              <> show len
              <> ") must be >= "
              <> show mI
              <> " and <= "
              <> show nI
              <> "."
  where
    mI :: Int
    mI = fromIntegral m

    nI :: Int
    nI = fromIntegral n

    -- Parse up to @n@ bytes where the predicate returns 'True'.
    transformState :: Word -> Word8 -> Maybe Word
    transformState s b
      | s == n = Nothing
      | s < n && f b = Just (s + 1)
      | otherwise = Nothing
