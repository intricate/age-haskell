{-# LANGUAGE CPP #-}

module Data.List.Compat
  ( unsnoc
  ) where

#if (MIN_VERSION_base(4,19,0))
import Data.List ( unsnoc )
#else
import Prelude
#endif


#if !(MIN_VERSION_base(4,19,0))
-- | \(\mathcal{O}(n)\). Decompose a list into 'init' and 'last'.
--
-- * If the list is empty, returns 'Nothing'.
-- * If the list is non-empty, returns @'Just' (xs, x)@,
-- where @xs@ is the 'init'ial part of the list and @x@ is its 'last' element.
--
--
-- 'unsnoc' is dual to 'uncons': for a finite list @xs@
--
-- > unsnoc xs = (\(hd, tl) -> (reverse tl, hd)) <$> uncons (reverse xs)
--
-- ==== __Examples__
--
-- >>> unsnoc []
-- Nothing
--
-- >>> unsnoc [1]
-- Just ([],1)
--
-- >>> unsnoc [1, 2, 3]
-- Just ([1,2],3)
--
-- ==== __Laziness__
--
-- >>> fst <$> unsnoc [undefined]
-- Just []
--
-- >>> head . fst <$> unsnoc (1 : undefined)
-- Just *** Exception: Prelude.undefined
--
-- >>> head . fst <$> unsnoc (1 : 2 : undefined)
-- Just 1
--
-- @since base-4.19.0.0
unsnoc :: [a] -> Maybe ([a], a)
-- The lazy pattern ~(a, b) is important to be productive on infinite lists
-- and not to be prone to stack overflows.
-- Expressing the recursion via 'foldr' provides for list fusion.
unsnoc = foldr (\x -> Just . maybe ([], x) (\(~(a, b)) -> (x : a, b))) Nothing
{-# INLINABLE unsnoc #-}
#endif
