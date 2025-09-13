{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Age.Armor
  ( tests
  ) where

import Control.Monad.Except ( runExceptT )
import Crypto.Age.Armor ( ArmorError (..), conduitArmor, conduitUnarmor )
import qualified Data.Conduit as C
import qualified Data.Conduit.Combinators as C
import qualified Data.Conduit.List as CL
import Data.Functor.Identity ( runIdentity )
import Hedgehog
  ( Property
  , annotateShow
  , checkParallel
  , discover
  , forAll
  , property
  , withTests
  , (===)
  )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'conduitArmor' and 'conduitUnarmor' round trip.
prop_roundTrip_conduitArmorUnarmor :: Property
prop_roundTrip_conduitArmorUnarmor = property $ do
  expected <- forAll $ Gen.bytes (Range.linear 1 1024)
  let sourceExpected = C.yield expected

  let encodedRes =
        runIdentity . runExceptT . C.runConduit $
          sourceExpected
            C..| conduitArmor
            C..| C.fold
  annotateShow encodedRes
  encoded <-
    case encodedRes of
      Left err -> fail $ "failed to armor: " <> show err
      Right x -> pure x

  let actualRes =
        runIdentity . runExceptT . C.runConduit $
          C.yield encoded
            C..| conduitUnarmor
            C..| C.fold
  actual <-
    case actualRes of
      Left err -> fail $ "failed to unarmor: " <> show err
      Right x -> pure x

  expected === actual

-- | Test that 'conduitArmor' fails when no data is pushed from upstream.
prop_conduitArmorFailsWithNullSource :: Property
prop_conduitArmorFailsWithNullSource = withTests 1 . property $ do
  let res =
        runIdentity . runExceptT . C.runConduit $
          CL.sourceNull
            C..| conduitArmor
            C..| C.fold
  case res of
    Left ArmorNoDataError -> pure ()
    Right _ -> fail $ "expected " <> show ArmorNoDataError <> " but got a success result"

-- | Test that 'conduitArmor' fails when only an empty 'ByteString' is pushed
-- from upstream.
prop_conduitArmorFailsWithEmptyByteString :: Property
prop_conduitArmorFailsWithEmptyByteString = withTests 1 . property $ do
  let res =
        runIdentity . runExceptT . C.runConduit $
          C.yield ""
            C..| conduitArmor
            C..| C.fold
  case res of
    Left ArmorNoDataError -> pure ()
    Right _ -> fail $ "expected " <> show ArmorNoDataError <> " but got a success result"
