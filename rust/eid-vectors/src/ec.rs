//! Minimal affine short-Weierstrass arithmetic over num-bigint, used only to
//! derive and self-check generated curve constants (never for verification).

use anyhow::{ensure, Result};
use num_bigint::BigUint;

/// Curve `y² = x³ + a·x + b` over `p`, with base point order `n`.
#[derive(Debug, Clone)]
pub(crate) struct Curve {
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub n: BigUint,
    pub g: (BigUint, BigUint),
}

/// `None` is the point at infinity.
pub(crate) type Point = Option<(BigUint, BigUint)>;

impl Curve {
    fn sub(&self, x: &BigUint, y: &BigUint) -> BigUint {
        (x + &self.p - (y % &self.p)) % &self.p
    }

    fn inv(&self, x: &BigUint) -> BigUint {
        x.modpow(&(&self.p - 2u8), &self.p)
    }

    pub fn on_curve(&self, (x, y): &(BigUint, BigUint)) -> bool {
        let rhs = (x * x * x + &self.a * x + &self.b) % &self.p;
        (y * y) % &self.p == rhs
    }

    pub fn add(&self, p1: &Point, p2: &Point) -> Point {
        let (Some((x1, y1)), Some((x2, y2))) = (p1, p2) else {
            return p1.clone().or_else(|| p2.clone());
        };
        let lambda = if x1 == x2 {
            if (y1 + y2) % &self.p == BigUint::ZERO {
                return None;
            }
            (BigUint::from(3u8) * x1 * x1 + &self.a) * self.inv(&(BigUint::from(2u8) * y1))
                % &self.p
        } else {
            self.sub(y2, y1) * self.inv(&self.sub(x2, x1)) % &self.p
        };
        let x3 = self.sub(&self.sub(&(&lambda * &lambda), x1), x2);
        let y3 = self.sub(&(lambda * self.sub(x1, &x3)), y1);
        Some((x3, y3))
    }

    pub fn mul(&self, k: &BigUint, point: &Point) -> Point {
        let mut acc: Point = None;
        for i in (0..k.bits()).rev() {
            acc = self.add(&acc, &acc);
            if k.bit(i) {
                acc = self.add(&acc, point);
            }
        }
        acc
    }

    /// Square root mod `p` for `p ≡ 3 (mod 4)`.
    pub fn sqrt(&self, v: &BigUint) -> Option<BigUint> {
        let y = v.modpow(&((&self.p + 1u8) >> 2u8), &self.p);
        ((&y * &y) % &self.p == v % &self.p).then_some(y)
    }

    /// Generator on the curve, of order `n`, and `p ≡ 3 (mod 4)`.
    pub fn check_domain(&self) -> Result<()> {
        ensure!(&self.p % 4u8 == BigUint::from(3u8), "p is not 3 mod 4");
        ensure!(self.on_curve(&self.g), "generator is not on the curve");
        ensure!(
            self.mul(&self.n, &Some(self.g.clone())).is_none(),
            "n\u{b7}G is not infinity"
        );
        Ok(())
    }
}
