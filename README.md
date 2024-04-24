# CAKE Python implementation

This is a Python implementation of the post-quantum password-authenticated key exchange algorithm CAKE.

This work is based on [the paper introducing CAKE](https://eprint.iacr.org/2023/470), as well as several implementation choices regarding the ideal cipher model.

This implementation is based on [`kyber-py`](https://github.com/GiacomoPope/kyber-py). For this reason, **it is not suitable for a production environment**. The C implementation should be relied on instead.

## Installation

Via Poetry.

## Code execution

Note that this is a package. Therefor, if you want to execute `tests.py` you will need to set your current working directory above the folder containing this repo. (for exemple, if this repo is in `~/git_repos/cakepython`, do `cd ~/git_repos`) and call

```sh
python -m cakepython.tests [TEST]
```

Where `[TEST]` is the test to be executed, in `feistel`, `public_key`, `cake` and `ocake`

## Usage

### For CAKE

```python
from cake import AliceCake, BobCake

alice = AliceCake(int(0).to_bytes(), b"password123")
bob = BobCake(int(0).to_bytes(), b"password123")

alice.generate_keypair()
bob.generate_symmetric_key(alice.encrypted_public_key, alice.name)
alice.decrypt_ciphertext(bob.encrypted_ciphertext, bob.name)

assert alice.session_key == bob.session_key  # Doesn't raise an error.
```

### For OCAKE

```python
from cake import AliceOCake, BobOCake

alice = AliceOCake(int(0).to_bytes(), b"password123")
bob = BobOCake(int(0).to_bytes(), b"password123")

alice.generate_keypair()
bob.generate_symmetric_key(alice.encrypted_public_key, alice.name)
alice.decrypt_ciphertext(bob.encrypted_ciphertext, bob.auth_verifier, bob.name)

assert alice.session_key == bob.session_key  # Doesn't raise an error.
```

## Class structure

```
Interocutor
│
└─── InterlocutorCake
│   └─── AliceCake
│   └─── BobCake
│
└───InterlocutorOCake
    └─── AliceOCake
    └─── BobOCake
```
