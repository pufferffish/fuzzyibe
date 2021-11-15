module Main where

import Protolude

import Data.Curve.Weierstrass (Point(A), gen, mul')
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
    (pkgPrivateKey, publicParams :: PublicParameter BLS12381 Fr) <- constructParameters d h
    print "creating alice identity"
    aliceIdentity <- Set.fromList <$> replicateM 8 (randomIO :: IO Fr)
    print "pkg creating key for alice"
    aliceKey <- keyGeneration publicParams pkgPrivateKey aliceIdentity
    print "creating random identity for testing"
    encryptIdentity <- Set.fromList . ((take (d+1) $ Set.toList aliceIdentity) `mappend`) <$> replicateM 5 (randomIO :: IO Fr)
    print "creating message"
    message <- randomIO :: IO (GT BLS12381)
    print "message:"
    print message
    print "encrypting"
    ciphertext <- encrypt publicParams encryptIdentity message
    print "alice decrypting"
    case decrypt publicParams aliceKey ciphertext of
        Nothing -> print "bruh"
        Just message' -> print $ message' == message

