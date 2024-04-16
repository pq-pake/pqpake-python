# CAKE Python implementation

This is a Python implementation of the post-quantum password-authenticated key exchange algorithm CAKE.

This work is based on [the paper introducing CAKE](https://eprint.iacr.org/2023/470), as well as several implementation choices regarding the ideal cipher model.

This implementation is based on [`kyber-py`](https://github.com/GiacomoPope/kyber-py). For this reason, **it is not suitable for a production environment**. The C implementation should be relied on instead.

## Installation

Via Poetry.

## Usage

```python
from cake import Alice, Bob
alice, bob = Alice(), Bob()
alice.generate_encrypted_public_key()
bob.generate_encrypted_cyphertext(alice.encrypted_public_key)
alice.decrypt_ciphertext(bob.encrypted_ciphertext)
assert alice.symmetric_key == bob.symmetric_key  # Doesn't raise an error.
```
