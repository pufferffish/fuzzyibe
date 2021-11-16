{-# LANGUAGE UndecidableInstances #-}

-- An attempt to wrap Crytonite's DRG in System.Random
-- Probably has a more efficent way of doing this
module FuzzyIBE.Random 
( randomCryptonite
, randomRCryptonite
)
where

import Protolude hiding (uncons)

import Crypto.Random
import Crypto.Number.Generate
import System.Random
import Data.ByteArray
import Data.Word

nextInt :: DRG gen => gen -> (Int, gen)
nextInt g = let intMinBound = fromIntegral (minBound :: Int)
                intMaxBound = fromIntegral (maxBound :: Int)
            in withDRG g (fromIntegral <$> generateBetween intMinBound intMaxBound)

instance RandomGen ChaChaDRG where
    next = nextInt
    split g = fst $ withDRG g $ do
        drg1 <- drgNew
        drg2 <- drgNew
        pure (drg1, drg2)
    genRange g = (minBound, maxBound)

randomCryptonite :: forall (m :: * -> *) a. (MonadRandom m, Random a) => m a
randomCryptonite = fst . random <$> drgNew

randomRCryptonite :: forall (m :: * -> *) a. (MonadRandom m, Random a) => (a, a) -> m a
randomRCryptonite r = fst . randomR r <$> drgNew

