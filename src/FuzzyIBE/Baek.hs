{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE UndecidableInstances #-}

module FuzzyIBE.Baek 
( randomScalar
, IdentityAttributes
, PKGPrivateParameter(..)
, PublicParameter(..)
, PrivateKey
, Ciphertext
, keyGeneration
, encrypt
, encryptDeterminsitic
, constructParameters
, decrypt
)
where

import Protolude

import Data.Bifunctor (first, second)
import Data.Curve (Curve, Form (Weierstrass))
import Data.Curve.Weierstrass (Point(A), gen, WCurve)
import Data.Field.Galois (fromP, toP, Prime, PrimeField, GaloisField)
import Data.Group (invert, Group)
import Data.HashSet (HashSet)
import Data.Hashable
import Data.List ((!!), delete, intersect, lookup)
import Data.Map (Map)
import Data.Pairing (Pairing, pairing, G1, G2, GT)
import Crypto.Number.Generate
import Crypto.Random.Types
import qualified Data.Curve.Weierstrass as W
import qualified Data.HashSet as Set
import qualified Data.Map as Map
import qualified Data.Group as Group

mul' :: (Curve f c e q r, PrimeField n) => Point f c e q r -> n -> Point f c e q r
mul' p = W.mul' p . fromP

pow :: (Group m, PrimeField x) => m -> x -> m
pow b = Group.pow b . fromP

-- Langrange coefficient
bigDelta :: (Fractional a, Eq a) => a -> [a] -> a -> a
bigDelta i s x = product $ f <$> s
    where f j | i == j = 1
              | otherwise = (x - j) / (i - j)

randomScalar :: forall m b. (Bounded b, PrimeField b, MonadRandom m) => m b
randomScalar = fromInteger <$> generateBetween 1 (fromP (maxBound :: b))

type IdentityAttributes r = HashSet r

newtype PKGPrivateParameter r = PKGPrivateParameter r

data PublicParameter a r = PublicParameter { 
  d :: Int -- error tolerance
, g1 :: G1 a
, g2 :: G2 a
, h :: r -> G1 a -- hash function from Identity to Point 
}

constructParameters :: forall (f :: Form) (c :: W.Coordinates) e q r a 
    (f2 :: Form) (c2 :: W.Coordinates) e2 q2 r2 (m :: * -> *). 
    ( Curve f c e q r
    , Curve f2 c2 e2 q2 r2
    , Pairing a
    , G2 a ~ Point f c e q r
    , G1 a ~ Point f2 c2 e2 q2 r2
    , MonadRandom m
    , Bounded r
    , PrimeField r
    , Group (G1 a)) => 
    Int -> (r -> G1 a) -> m (PKGPrivateParameter r, PublicParameter a r)
constructParameters d h = do
    s <- randomScalar :: m r
    g1 <- pow (gen :: G1 a) <$> (randomScalar :: m r)
    let g2 = pow gen s
    return (PKGPrivateParameter s, PublicParameter d g1 g2 h)

newtype PrivateKey r a = PrivateKey (Map r (G1 a, G2 a))

data Ciphertext r a = Ciphertext (Map r (G1 a)) (G2 a) (GT a)

instance Show (Point f c e q r) => Hashable (Point f c e q r) where
    hashWithSalt i p = hashWithSalt i x
        where x = show p :: [Char]

setAssocMap f set = Map.fromList $ Set.toList $ Set.map (\x -> (x, f x)) set

keyGeneration
  :: (Curve f c e q r, MonadRandom m, Group (G1 a), G2 a ~ Point f c e q r, Bounded r, Hashable r, Hashable (G1 a), Eq (G1 a)) =>
     PublicParameter a r -> PKGPrivateParameter r -> IdentityAttributes r -> m (PrivateKey r a)
keyGeneration (PublicParameter d g1 g2 h) (PKGPrivateParameter s) identity = do
    cef <- (s :) <$> replicateM (d-1) randomScalar
    return $ PrivateKey $ setAssocMap (alpha (poly cef)) identity
    where
        alpha p mui = 
            let pmui = p mui 
            in (pow (h mui) pmui, pow gen pmui)
        poly cef x = sum $ (\(a,b) -> a * Group.pow x b) <$> zip cef [0..]

encrypt
  :: (Curve f c e q r, Pairing a, PrimeField r, Bounded r, G2 a ~ Point f c e q r, Hashable r, Hashable (G1 a), MonadRandom m) =>
     PublicParameter a r
     -> IdentityAttributes r
     -> GT a
     -> m (Ciphertext r a)
encrypt p@(PublicParameter d g1 g2 h) identity message = encryptDeterminsitic p identity message <$> randomScalar

encryptDeterminsitic
  :: (Curve f c e q r, Pairing a, PrimeField r, G2 a ~ Point f c e q r, Hashable r, Hashable (G1 a)) =>
     PublicParameter a r
     -> IdentityAttributes r
     -> GT a
     -> r
     -> Ciphertext r a
encryptDeterminsitic (PublicParameter d g1 g2 h) identity message r = 
    let gr = pow gen r
        w = pow (pairing g1 g2) r <> message
    in Ciphertext (setAssocMap alpha identity) gr w
    where
        alpha mui = pow (g1 <> h mui) r

decrypt
  :: (Pairing e1, Curve f1 c1 e2 q1 r1, Curve f2 c2 e3 q2 r1, PrimeField r1,
      G1 e1 ~ Point f2 c2 e3 q2 r1, G2 e1 ~ Point f1 c1 e2 q1 r1) =>
     PublicParameter e1 r1 -> PrivateKey r1 e1 -> Ciphertext r1 e1 -> Maybe (GT e1)
decrypt (PublicParameter d g1 g2 h) (PrivateKey keyPair) (Ciphertext idv u w) 
    | length s /= d = Nothing
    | otherwise = Just $ a <> invert b <> w
    where
        a = flip pairing u $ fold $ Map.mapWithKey (\mu (gamma,x) -> 
              mul' gamma $ bigDelta mu s 0) privateKey
        b = fold $ Map.mapWithKey (\mu (x,delta) -> 
              let Just v' = Map.lookup mu idv
              in pairing v' $ mul' delta $ bigDelta mu s 0) privateKey
        privateKey = Map.filterWithKey (\mu _ -> mu `elem` s) keyPair
        s = take d $ intersect (Map.keys keyPair) $ Map.keys idv

