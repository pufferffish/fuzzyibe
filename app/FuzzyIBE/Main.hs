module Main where

import Protolude

import Data.Curve (Curve)
import Data.Curve.Weierstrass (Point(A), gen)
import Data.Field.Galois (fromP, toP, Prime, PrimeField)
import Data.Group (pow, invert)
import Data.List ((!!), delete, intersect, lookup)
import Data.Map (Map)
import Data.Pairing.BLS12381 (BLS12381, G1, G2, GT, pairing, Fr)
import Data.Set (Set)
import System.Random
import qualified Data.Curve.Weierstrass as W
import qualified Data.Map as Map

mul' :: (Curve f c e q r, PrimeField n) => Point f c e q r -> n -> Point f c e q r
mul' p = W.mul' p . fromP

-- Langrange coefficient
bigDelta :: Fr -> [Fr] -> Fr -> Fr
bigDelta i s x = product $ f <$> delete i s
    where f j = (x - j) / (i - j)

type IdentityAttributes = [Fr]

type HashFunction = Fr -> G1 BLS12381

data PrivateKey = PrivateKey IdentityAttributes [(G1 BLS12381, G2 BLS12381)]

data Ciphertext = Ciphertext IdentityAttributes (G2 BLS12381) [G1 BLS12381] (GT BLS12381)

keyGeneration :: Int -> Fr -> HashFunction -> IdentityAttributes -> IO PrivateKey
keyGeneration d s h identity = do
    cef <- (s :) <$> replicateM (d-1) (randomIO :: IO Fr)
    return $ PrivateKey identity (dee (poly cef) <$> identity)
    where
        dee p mui = 
            let pmui = fromP $ p mui 
            in (pow (h mui) pmui, pow gen pmui)
        poly cef x = sum $ (\(a,b) -> a * pow x b) <$> zip cef [0..]

-- g1 is randomly chosen
-- g2 = gen^s
encrypt :: G1 BLS12381 -> G2 BLS12381 -> HashFunction -> IdentityAttributes -> GT BLS12381 -> IO Ciphertext
encrypt g1 g2 h identity message = do
    r <- fromP <$> (randomIO :: IO Fr)
    let gr = pow gen r
    let w = pow (pairing g1 g2) r <> message
    return $ Ciphertext identity gr (alpha r <$> identity) w
    where
        alpha r mui = pow (g1 <> h mui) r

decrypt :: Int -> PrivateKey -> Ciphertext -> Maybe (GT BLS12381)
decrypt d (PrivateKey identity key) (Ciphertext identity' u v w) 
    | length s /= d = Nothing
    | otherwise = Just $ a <> invert b <> w
    where
        a = let alpha = filter (\(mu,x) -> mu `elem` s) $ zip identity $ fst <$> key
                beta = fold $ (\(mu,gamma) -> mul' gamma $ bigDelta mu s 0) <$> alpha
            in pairing beta u
        b = let alpha = filter (\(mu,x) -> mu `elem` s) $ zip identity $ snd <$> key
                beta = zip identity' v
            in fold $ (\(mu,delta) -> 
                let Just v' = lookup mu beta
                in pairing v' $ mul' delta $ bigDelta mu s 0) <$> alpha
        s = take d $ intersect identity identity'

main :: IO ()
main = do
    putText "joe mama"
    let d = 5
    let h = pow gen . fromP
    s <- randomIO :: IO Fr -- master key of the PKG
    g1 <- randomIO :: IO (G1 BLS12381) -- public
    let g2 = mul' gen s :: G2 BLS12381 -- public
    print "creating alice identity"
    aliceIdentity <- replicateM 8 (randomIO :: IO Fr)
    print "pkg creating key for alice"
    aliceKey <- keyGeneration d s h aliceIdentity
    print "creating random identity for testing"
    encryptIdentity <- (take (d+1) aliceIdentity ++) <$> replicateM 5 (randomIO :: IO Fr)
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
