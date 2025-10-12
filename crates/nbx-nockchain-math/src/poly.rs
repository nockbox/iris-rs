#![allow(clippy::len_without_is_empty)]

extern crate alloc;
use crate::belt::Belt;
use alloc::vec::Vec;
use core::slice::Iter;

pub trait Element: Clone {
    fn is_zero(&self) -> bool;
    fn zero() -> Self;
}

impl Element for Belt {
    #[inline(always)]
    fn is_zero(&self) -> bool {
        self.is_zero()
    }
    #[inline(always)]
    fn zero() -> Self {
        Belt::zero()
    }
}

pub trait Poly {
    type Element: Element;

    fn data(&self) -> &[Self::Element];

    #[inline(always)]
    fn degree(&self) -> u32 {
        self.data()
            .iter()
            .rposition(|x| !Element::is_zero(x))
            .map_or(0, |i| i as u32)
    }

    #[inline(always)]
    fn is_zero(&self) -> bool {
        let len = self.len();
        let data = self.data();
        if len == 0 || (len == 1 && data[0].is_zero()) {
            return true;
        }
        data.iter().all(|x| x.is_zero())
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.data().len()
    }

    #[inline(always)]
    fn iter(&self) -> Iter<'_, Self::Element> {
        self.data().iter()
    }
}

impl<T> Poly for &[T]
where
    T: Element,
{
    type Element = T;
    #[inline(always)]
    fn data(&self) -> &[T] {
        self
    }
}

impl<T> Poly for Vec<T>
where
    T: Element,
{
    type Element = T;
    #[inline(always)]
    fn data(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T> Poly for &mut [T]
where
    T: Element,
{
    type Element = T;
    #[inline(always)]
    fn data(&self) -> &[T] {
        self
    }
}
