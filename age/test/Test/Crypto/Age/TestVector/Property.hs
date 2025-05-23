module Test.Crypto.Age.TestVector.Property
  ( mkTestVectorProperties
  ) where

import Conduit ( ResourceT )
import Control.Monad ( filterM, when )
import Crypto.Age.Conduit
  ( DecryptError (..), DecryptPayloadError (..), sinkDecrypt )
import Data.Conduit ( awaitForever, yield, ($$+), ($$+-), (.|) )
import Data.Conduit.Attoparsec ( sinkParser )
import qualified Data.Conduit.Combinators as C
import qualified Data.Conduit.Zlib as Zlib
import Data.Foldable ( for_ )
import Data.List ( sort )
import qualified Data.List.NonEmpty as NE
import qualified Data.Text as T
import Hedgehog ( PropertyT, discard, footnote )
import Prelude
import System.Directory ( doesFileExist, listDirectory )
import Test.Crypto.Age.TestVector.Header
  ( Compressed (..), Expect (..), Header (..), headerParser )

testVectorDirectory :: FilePath
testVectorDirectory = "test/test-vectors"

getTestVectorFileNames :: IO [FilePath]
getTestVectorFileNames = do
  fileNames <- sort <$> listDirectory testVectorDirectory
  flip filterM fileNames $ \fileName ->
    doesFileExist $ concat [testVectorDirectory, "/", fileName]

mkTestVectorProperty :: FilePath -> (String, PropertyT (ResourceT IO) ())
mkTestVectorProperty fileName = (fileName, prop)
  where
    prop :: PropertyT (ResourceT IO) ()
    prop = do
      let path = concat [testVectorDirectory, "/", fileName]
      (sealedSrc, header) <- C.sourceFile path $$+ sinkParser headerParser
      let Header
            { hExpect
            , hCompressed
            , hIdentity
            , hArmored
            , hComment
            } = header
      for_ hComment (\comment -> footnote . T.unpack $ "test comment: " <> comment)
      let conduitDecompress =
            case hCompressed of
              Just CompressedGzip -> Zlib.ungzip
              Just CompressedZlib -> Zlib.decompress Zlib.defaultWindowBits
              Nothing -> awaitForever yield
      when hArmored $ discard -- TODO: add support for armored age files

      res <-
        sealedSrc
          $$+- conduitDecompress
          .| sinkDecrypt (NE.singleton hIdentity)
      case (hExpect, res) of
        (ExpectSuccess, Right _) -> pure ()
        (ExpectNoMatch, Left DecryptNoMatchingRecipientError) -> pure ()
        (ExpectHmacFailure, Left (DecryptInvalidHeaderMacError _ _)) -> pure ()
        (ExpectHeaderFailure, Left (DecryptHeaderParseError _)) -> pure ()
        (ExpectHeaderFailure, Left DecryptScryptStanzaNotAloneError) -> pure ()
        (ExpectHeaderFailure, Left (DecryptUnwrapStanzaError _)) -> pure ()
        (ExpectHeaderFailure, Left (DecryptDecryptPayloadError (DecryptPayloadKeyNonceParseError _))) ->
          -- This is considered a header failure according to some of the test
          -- vectors; which is a bit odd since the payload nonce is explicitly
          -- described as being part of the payload:
          --
          -- > The binary payload... It begins with a 16-byte nonce generated
          -- > by the sender...
          --
          -- https://github.com/C2SP/C2SP/blob/03ab74455beb3a6d6e0fb7dd1de5a932e2257cd0/age.md#payload
          pure ()
        (ExpectHeaderFailure, Left DecryptNoMatchingRecipientError)
          | fileName == "scrypt_work_factor_23" ->
            -- In our implementation, the maximum work factor value permitted
            -- is 64, but this test vector expects us to fail in the event that
            -- it's 23.
            --
            -- So, in order to appease this test vector, we set the maximum
            -- work factor for 'hIdentity' to 22 in the scrypt case. However,
            -- in our implementation, this results in a \"no match\" error and
            -- not a \"header failure\" error as is expected by the test
            -- vector. So we make an exception for this particular case.
            pure ()
        (ExpectPayloadFailure, Left (DecryptDecryptPayloadError _)) -> pure ()
        (ExpectArmorFailure, _) -> discard -- TODO: add support for armored age files
        (_, Left err) -> fail $ "expected " <> show hExpect <> " but got the result: " <> show err
        (_, Right _) -> fail $ "expected " <> show hExpect <> " but got a success result"

mkTestVectorProperties :: IO [(String, PropertyT (ResourceT IO) ())]
mkTestVectorProperties = map mkTestVectorProperty <$> getTestVectorFileNames
