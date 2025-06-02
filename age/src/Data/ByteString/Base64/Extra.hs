{-# LANGUAGE CPP #-}

module Data.ByteString.Base64.Extra
  ( encodeBase64StdUnpadded
  , decodeBase64StdUnpadded
  ) where

#if MIN_VERSION_base64(1,0,0)
import qualified Data.Base64.Types as B64
#endif
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.URL as B64URL
import Data.Text ( Text )
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Prelude

encodeBase64StdUnpadded :: ByteString -> ByteString
encodeBase64StdUnpadded =
  -- Drop padding bytes ('=') from the end of the base64 string.
  (BS.dropWhileEnd (== 0x3D))
#if MIN_VERSION_base64(1,0,0)
    . B64.extractBase64
#endif
    . B64.encodeBase64'

decodeBase64StdUnpadded :: ByteString -> Either Text ByteString
decodeBase64StdUnpadded b64 =
  -- The @base64@ library does not support decoding unpadded standard base64.
  -- So we're going to convert to base64url and then decode.
  let b64Url :: ByteString
      b64Url = TE.encodeUtf8 (T.replace "+" "-" $ T.replace "/" "_" $ TE.decodeUtf8 b64)
  in
#if MIN_VERSION_base64(1,0,0)
    B64URL.decodeBase64UnpaddedUntyped b64Url
#else
    B64URL.decodeBase64Unpadded b64Url
#endif
