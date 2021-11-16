import Protolude

import Data.Curve.Weierstrass (Point(A), gen)
import Data.Field.Galois (fromP, toP, Prime, PrimeField, GaloisField)
import Data.Group (pow)
import Data.Pairing.BLS12381 (BLS12381, Fr, G1, G2, GT)
import FuzzyIBE.Baek
import FuzzyIBE.Random
import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.HashSet as Set

tests :: TestTree
tests = testGroup "FuzzyIBE"
  [ testGroup "Baek"
    [ baekTestCorrectEncryptDecrypt
    ]
  ]

baekTestCorrectEncryptDecrypt :: TestTree
baekTestCorrectEncryptDecrypt = testCase "D(E(m)) = m" $ do
    let d = 5
    let h = pow gen . fromP . pow (7 :: Fr)
    (pkgPrivateKey, publicParams :: PublicParameter BLS12381 Fr) <- constructParameters d h
    aliceIdentity <- Set.fromList <$> replicateM 8 (randomCryptonite :: IO Fr)
    aliceKey <- keyGeneration publicParams pkgPrivateKey aliceIdentity
    encryptIdentity <- Set.fromList . ((take (d+1) $ Set.toList aliceIdentity) `mappend`) <$> replicateM 5 (randomCryptonite :: IO Fr)
    message <- randomCryptonite :: IO (GT BLS12381)
    ciphertext <- encrypt publicParams encryptIdentity message

    case decrypt publicParams aliceKey ciphertext of
        Nothing -> assertFailure "Alice does not have sufficent credential"
        Just message' -> 
            if message' == message then pure ()
            else assertFailure "Failed to correctly decrypt message"

main :: IO ()
main = defaultMain tests
