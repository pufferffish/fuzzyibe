{-# LANGUAGE AllowAmbiguousTypes #-}

module Main where

import Protolude

import Data.Curve (Curve, Form (Weierstrass))
import Data.Curve.Weierstrass (Point(A), gen, WCurve)
import Data.Field.Galois (fromP, toP, Prime, PrimeField, GaloisField)
import Data.Group (pow, invert, Group)
import Data.List ((!!), delete, intersect, lookup)
import Data.Map (Map)
import Data.Pairing (Pairing, pairing, G1, G2, GT)
import Data.Pairing.BLS12381 (BLS12381, Fr)
import Data.Set (Set)
import System.Random
import qualified Data.Curve.Weierstrass as W
import qualified Data.Map as Map

mul' :: (Curve f c e q r, PrimeField n) => Point f c e q r -> n -> Point f c e q r
mul' p = W.mul' p . fromP

-- Langrange coefficient
bigDelta :: (Fractional a, Eq a) => a -> [a] -> a -> a
bigDelta i s x = product $ f <$> delete i s
    where f j = (x - j) / (i - j)

type IdentityAttributes r = [r]

data PrivateKey r a = PrivateKey (IdentityAttributes r) [(G1 a, G2 a)]

data Ciphertext r a = Ciphertext (IdentityAttributes r) (G2 a) [G1 a] (GT a)

keyGeneration
  :: (Curve f c e q r, MonadIO m, PrimeField k,
     Group (G1 a), G2 a ~ Point f c e q r) =>
     Int
     -> k -> (k -> G1 a) -> IdentityAttributes k -> m (PrivateKey k a)
keyGeneration d s h identity = do
    cef <- (s :) <$> replicateM (d-1) randomIO 
    return $ PrivateKey identity (dee (poly cef) <$> identity)
    where
        dee p mui = 
            let pmui = fromP $ p mui 
            in (pow (h mui) pmui, pow gen pmui)
        poly cef x = sum $ (\(a,b) -> a * pow x b) <$> zip cef [0..]

encrypt
  :: (Curve f c e q r, Pairing a, G2 a ~ Point f c e q r) =>
     G1 a
     -> Point f c e q r
     -> (t -> G1 a)
     -> IdentityAttributes t
     -> GT a
     -> IO (Ciphertext t a)
encrypt g1 g2 h identity message = encryptDeterminsitic g1 g2 h identity message <$> (randomIO :: IO Fr)

encryptDeterminsitic
  :: (Curve f c e q r, Pairing a, PrimeField k, G2 a ~ Point f c e q r) =>
     G1 a
     -> Point f c e q r
     -> (t -> G1 a)
     -> IdentityAttributes t
     -> GT a
     -> k
     -> Ciphertext t a
encryptDeterminsitic g1 g2 h identity message r = 
    let r' = fromP r -- pow with Fr exponent will get stuck for some reason
        gr = pow gen r'
        w = pow (pairing g1 g2) r' <> message
    in Ciphertext identity gr (alpha r' <$> identity) w
    where
        alpha r' mui = pow (g1 <> h mui) r'

decrypt
  :: (Pairing e1, Curve f1 c1 e2 q1 r1, Curve f2 c2 e3 q2 r2,
      PrimeField a, G2 e1 ~ Point f1 c1 e2 q1 r1,
      G1 e1 ~ Point f2 c2 e3 q2 r2) =>
     Int -> PrivateKey a e1 -> Ciphertext a e1 -> Maybe (GT e1)
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
