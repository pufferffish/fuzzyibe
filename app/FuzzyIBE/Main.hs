module Main where

import Protolude

import Data.Curve.Weierstrass (Point(A), gen)
import Data.Field.Galois (fromP, toP, Prime, PrimeField, GaloisField)
import Data.Group (pow)
import Data.Pairing.BLS12381 (BLS12381, Fr, G1, G2, GT)
import FuzzyIBE.Baek
import System.Random
import qualified Data.HashSet as Set

main :: IO ()
main = do
    putText "joe mama"
    let d = 5
    let h = pow gen . fromP . pow (7 :: Fr)
    s <- randomIO :: IO Fr -- master key of the PKG
    g1 <- randomIO :: IO (G1 BLS12381) -- public
    let g2 = mul' gen s :: G2 BLS12381 -- public
    print "creating alice identity"
    aliceIdentity <- Set.fromList <$> replicateM 8 (randomIO :: IO Fr)
    print "pkg creating key for alice"
    aliceKey <- keyGeneration d s h aliceIdentity
    print "creating random identity for testing"
    encryptIdentity <- Set.fromList . ((take (d+1) $ Set.toList aliceIdentity) `mappend`) <$> replicateM 5 (randomIO :: IO Fr)
    print "creating message"
    message <- randomIO :: IO (GT BLS12381)
    print "message:"
    print message
    print "encrypting"
    ciphertext <- encrypt g1 g2 h encryptIdentity message
    print "alice decrypting"
    case decrypt d aliceKey ciphertext of
        Nothing -> print "bruh"
        Just message' -> print $ message' == message

