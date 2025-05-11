module Test.Crypto.Age.TestVector
  ( tests
  ) where

import Conduit ( runResourceT )
import Control.Monad.IO.Class ( MonadIO (..) )
import Control.Monad.Morph ( MFunctor (hoist) )
import Data.String ( fromString )
import Hedgehog ( Group (..), checkParallel, property, withDiscards, withTests )
import Prelude
import Test.Crypto.Age.TestVector.Property ( mkTestVectorProperties )

tests :: IO Bool
tests = testVectors >>= checkParallel

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

testVectors :: MonadIO m => m Group
testVectors = do
  props <- liftIO mkTestVectorProperties
  pure $ Group "Test Vectors (https://age-encryption.org/testkit)" $
    flip map props $ \(propName, prop) ->
      (fromString propName, withTests 1 . withDiscards 1 . property $ hoist runResourceT prop)
