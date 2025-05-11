{-# LANGUAGE CPP #-}

module Data.Conduit.Base64
  ( conduitEncodeBase64
  , conduitDecodeBase64
  ) where

import Control.Exception ( assert )
import Control.Monad.Except ( ExceptT, throwError )
import Control.Monad.Trans.Class ( MonadTrans (lift) )
import Data.Text ( Text )
#if MIN_VERSION_base64(1,0,0)
import qualified Data.Base64.Types as B64
#endif
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.Conduit ( ConduitT, await, yield )
import Data.MonoTraversable ( olength )
import Prelude

conduitEncodeBase64 :: Monad m => ConduitT ByteString ByteString m ()
conduitEncodeBase64 =
  codeWith 3
#if MIN_VERSION_base64(1,0,0)
    (Right . B64.extractBase64 . B64.encodeBase64')
#else
    (Right . B64.encodeBase64')
#endif
    (error "conduitEncodeBase64: impossible: base64 encoding cannot fail")

conduitDecodeBase64 :: Monad m => ConduitT ByteString ByteString (ExceptT Text m) ()
conduitDecodeBase64 =
  codeWith 4
#if MIN_VERSION_base64(1,0,0)
    B64.decodeBase64Untyped
#else
    B64.decodeBase64
#endif
    (lift . throwError)

codeWith ::
  Monad m =>
  Int ->
  -- | Encoding or decoding function.
  (ByteString -> Either e ByteString) ->
  -- | Error handling function.
  (e -> ConduitT ByteString ByteString m ()) ->
  ConduitT ByteString ByteString m ()
codeWith size f handleErr =
    loop
  where
    loop = await >>= maybe (return ()) push

    loopWith bs
        | BS.null bs = loop
        | otherwise = await >>= maybe (finish bs) (pushWith bs)

    finish bs =
        case f bs of
            Left err -> handleErr err
            Right x -> yield x

    push bs = do
        let (x, y) = BS.splitAt (len - (len `mod` size)) bs
        if BS.null x
            then loopWith y
            else do
                case f x of
                    Left err -> handleErr err
                    Right x' -> yield x' >> loopWith y
      where
        len = olength bs

    pushWith bs1 bs2 | BS.length bs1 + BS.length bs2 < size = loopWith (BS.append bs1 bs2)
    pushWith bs1 bs2 = assertion1 $ assertion2 $ assertion3 $
        case f bs1' of
            Left err -> handleErr err
            Right toYield -> yield toYield >> push y
      where
        m = BS.length bs1 `mod` size
        (x, y) = BS.splitAt (size - m) bs2
        bs1' = mappend bs1 x

        assertion1 = assert $ olength bs1 < size
        assertion2 = assert $ olength bs1' `mod` size == 0
        assertion3 = assert $ olength bs1' > 0
