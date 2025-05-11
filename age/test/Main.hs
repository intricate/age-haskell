module Main where

import Hedgehog.Main ( defaultMain )
import Prelude
import qualified Test.Crypto.Age.Conduit
import qualified Test.Crypto.Age.Header
import qualified Test.Crypto.Age.Identity
import qualified Test.Crypto.Age.Key
import qualified Test.Crypto.Age.Recipient
import qualified Test.Crypto.Age.Scrypt
import qualified Test.Crypto.Age.TestVector

main :: IO ()
main =
  defaultMain
    [ Test.Crypto.Age.Conduit.tests
    , Test.Crypto.Age.Header.tests
    , Test.Crypto.Age.Identity.tests
    , Test.Crypto.Age.Key.tests
    , Test.Crypto.Age.Recipient.tests
    , Test.Crypto.Age.Scrypt.tests
    , Test.Crypto.Age.TestVector.tests
    ]
