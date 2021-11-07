module Main where

import Protolude

import Data.Group (pow, invert)
import Data.Curve.Weierstrass (Point(A), gen)
import qualified Data.Curve.Weierstrass as W

import Data.Pairing.BLS12381 (BLS12381, G1, G2, pairing, Fr)
import Data.Curve (Curve)
import Data.Field.Galois (fromP, toP, Prime, PrimeField)

import Data.Set (Set)
import qualified Data.Set as Set

import System.Random
import Data.List ((!!))

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
delta :: Fr -> Set Fr -> Fr -> Fr
delta i s x = product $ f <$> Set.toList (Set.delete i s)
    where f j = (x - j) / (i - j)

capitalT :: [G1 BLS12381] -> G1 BLS12381 -> Fr -> G1 BLS12381 
capitalT t g2 x = a <> b
    where a = pow g2 $ fromP (x * toP n)
          b = fold (f <$> n')
          f (t', i) = pow t' (delta i n'' x)
          n = toInteger $ length t 
          n' = zip t [1..]
          n'' = Set.fromList $ toP <$> [1..(n+1)]

main :: IO ()
main = do
  let n = 4
  t <- replicateM n (randomIO :: IO (G1 BLS12381))
  print $ capitalT t g2 10
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
