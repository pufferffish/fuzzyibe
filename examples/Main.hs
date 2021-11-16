module Main where

import Protolude

import Crypto.Number.Generate
import Crypto.Random
import Crypto.Random.Types
import Data.Curve.Weierstrass (Point(A), gen, mul')
import Data.Field.Galois (fromP, toP, Prime, PrimeField, GaloisField)
import Data.Group (pow)
import Data.Hashable
import Data.Pairing.BLS12381 (BLS12381, Fr, G1, G2, GT)
import FuzzyIBE.Baek
import FuzzyIBE.Random
import qualified Data.HashSet as Set

-- Encode strings like "manager" into Z/pZ
-- Each attribute should be a unique integer 
-- Here I simply used `hash` from Data.Hashable
hashStringToFr :: Set.HashSet [Char] -> Set.HashSet Fr
hashStringToFr = Set.map (toP . fromIntegral . hash) 

-- This function is integral to the encryption process
-- The function takes an identity (integer over a Galois field)
-- and hash it to a point on left group of your bilinear operation
-- The output's randomness MUST be cryptographically secure
--
-- Here I used the input as a seed for a ChaCha determinstic random generator
-- which is then used to generate a number uniformly randomly in the Galois field
-- The generated number is then multiplied with the generator point
--
-- Note that supplying mul'/pow with a PrimeField will cause it to get stuck,
-- not sure why
hashFrToPoint :: Fr -> G1 BLS12381
hashFrToPoint fr = mul' gen $ fromP ((fst $ withDRG drg randomScalar) :: Fr)
    where 
        drg = drgNewSeed $ seedFromInteger $ fromP fr

main :: IO ()
main = do
    let d = 2 -- d is the error tolerance factor, in the example we set it to 2

    -- Construct the parameters, pkgPrivateKey should only be known by the Private Key Generator
    -- publicParams is shared to everyone involved in the system
    print "constructing parameters"
    (pkgPrivateKey, publicParams :: PublicParameter BLS12381 Fr) <- constructParameters d hashFrToPoint

    print "creating Alice identity"
    let aliceIdentity = hashStringToFr $ Set.fromList ["accounting depeartment", "senior staff", "manager"]

    print "pkg creating key for Alice"
    aliceKey <- keyGeneration publicParams pkgPrivateKey aliceIdentity

    -- Here Bob encrypts a message for the following attributes
    let encryptIdentity = hashStringToFr $ Set.fromList ["manager", "IT department", "senior staff", "CEO"]

    -- We randomly generate a message which is encoded as a point on an elliptic curve
    -- In practice you wouldn't try to encode message into a point, but rather generate a random point,
    -- which is then used to derive an encryption key for a symmeteric cipher of your choosing (e.g. AES)
    -- The plaintext is encrypted with the derived key, and the point is encrypted with the Fuzzy IBE scheme.
    print "creating message"
    message <- randomCryptonite :: IO (GT BLS12381)
    print "message:"
    print message


    print "encrypting"
    ciphertext <- encrypt publicParams encryptIdentity message

    print "alice decrypting"
    case decrypt publicParams aliceKey ciphertext of
        Nothing -> print "cannot decrypt"
        Just message' -> print $ message' == message

