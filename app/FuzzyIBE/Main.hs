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

y :: Fr
y = 2391049785704108062206460176992743369171336801136428757185510197763030434892923936573505657337893227059857166120

g1 :: G1 BLS12381
g1 = mul' gen y

g2 :: G1 BLS12381
g2 = mul' gen (3857874365743587436587435743658743 :: Fr) -- randomly chosen

p :: G1 BLS12381
p = mul' gen (3432432432432432432 :: Fr)

q :: G2 BLS12381
q = mul' gen (837587436533242 :: Fr)

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

decrypt :: Int -> IdentityAttributes -> PrivateKey -> Ciphertext -> Maybe (GT BLS12381)
decrypt d identity (PrivateKey keyId key) (Ciphertext identity' u v w) 
    | length s /= d = Nothing
    | otherwise = Just $ a <> invert b <> w
    where
        a = let alpha = zip keyId $ fst <$> key
                beta = fold $ (\(mu,gamma) -> mul' gamma $ bigDelta mu s 0) <$> alpha
            in pairing beta u
        b = let alpha = zip keyId $ snd <$> key
                beta = zip identity' v
            in fold $ (\(mu,delta) -> 
                let Just v' = lookup mu beta
                in pairing v' $ mul' delta $ bigDelta mu s 0) <$> alpha
        s = take d $ intersect identity identity'

main :: IO ()
main = do
  let n = 11
  t <- replicateM n (randomIO :: IO (G1 BLS12381))
  -- print $ capitalT t g2 10
  putText "P:"
  -- print p
  putText "Q:"
  -- print q
  putText "e(P, Q):"
  -- print (pairing p q)
  putText "e(P, Q) is bilinear:"
  -- print $ (pairing (mul' p $ b / a) (mul' q a)) == (pow (pairing p q) $ fromP b)
  where
    a = 343589748935193532478232933756825304602106207488058460712643352775646519130098395102608149477650462734276615378482 :: Fr
    b = 2769269168754130569474552972236904986905114131799047802595049097418455054134936404134120240363874383150058360924296 :: Fr
