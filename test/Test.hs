import Protolude

import Data.Curve.Weierstrass (Point(A), gen)
import Data.Field.Galois (fromP, toP, Prime, PrimeField, GaloisField)
import Data.Group (pow)
import Data.Pairing.BLS12381 (BLS12381, Fr, G1, G2, GT)
import FuzzyIBE.Baek
import System.Random
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
    s <- randomIO :: IO Fr -- master key of the PKG
    g1 <- randomIO :: IO (G1 BLS12381) -- public
    let g2 = mul' gen s :: G2 BLS12381 -- public
    -- creating alice identity
    aliceIdentity <- Set.fromList <$> replicateM 8 (randomIO :: IO Fr)
    aliceKey <- keyGeneration d s h aliceIdentity

    encryptIdentity <- Set.fromList . ((take (d+1) $ Set.toList aliceIdentity) `mappend`) <$> replicateM 5 (randomIO :: IO Fr)
    message <- randomIO :: IO (GT BLS12381)
    ciphertext <- encrypt g1 g2 h encryptIdentity message

    case decrypt d aliceKey ciphertext of
        Nothing -> assertFailure "Alice does not have sufficent credential"
        Just message' -> 
            if message' == message then pure ()
            else assertFailure "Failed to correctly decrypt message"

main :: IO ()
main = defaultMain tests
