# fuzzyibe
A Haskell implementation of Fuzzy Identity Based Encryption, based on [Baek et al (2007)](https://eprint.iacr.org/2007/047.pdf "Baek et al (2007)"), modified to work over asymmetric bilinear pairing.

## What is Fuzzy IBE
Fuzzy [Identity Based Encryption](https://en.wikipedia.org/wiki/Identity-based_encryption "Identity Based Encryption") is a form of IBE which allows using  a set of attributes as an identity, while allowing a margin of error tolerance. For example, assume that Alice and Bob are in a Fuzzy IBE system where error tolerance is set to 2 *(d=2)*. Alice can possess the identity of {"accounting department", "senior staff", "manager"}, and Bob can encrypt a message encrypted for {"manager", "IT department", "senior staff", "CEO"}. Since Alice posseses 2 of the attributes ("senior staff", "manager"), Alice can decrypt the message, whereas she wouldn't be able to decrypt a message encrypted for {"manager", "IT department", "junior staff", "CEO"}, since Alice does not process at least *d* common attributes.

## Example
An example implementation of the aforementioned scenario can be found in [Main.hs](app/Main.hs).

## Disclaimer
This project is created as a hobbyist project, and is not intended for any serious usage. The operations provided in the library, and elliptic curve library that this project is based on, are suspectible to timing attacks. Use at your own risk.

## License
See [LICENSE](LICENSE).

