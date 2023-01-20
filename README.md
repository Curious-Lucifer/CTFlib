# CTFlib

## Requirement
pip : 
```
gmpy2
pycryptodome
pwntools
factordb-pycli
```
apt :
```
sagemath
```

---

## Usage
```python
import sys
sys.path.append('<path of CTFlib>')

from CTFlib.Crypto.RSA import *
from CTFlib.Crypto.Block_Cipher import *
from CTFlib.Crypto.PRNG import *

'''
already import :

from math import gcd
from gmpy2 import iroot
from functools import reduce
from sage.all import var, Integer, NonNegativeIntegerSemiring, Zmod, PolynomialRing, IntegerRing, ceil, floor, GF
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from pwn import xor
from factordb.factordb import FactorDB
'''

# sage : Z.<x> = PolynoamialRing(Zmod(n),implementation='NTL')
# Z = PolynomialRing(Zmod(n),implementation='NTL', names=('x',)); (x,) = Z._first_ngens(1)

# sage : Z.<x> = PolynomialRing(ZZ)
# Z = PolynomialRing(ZZ, names=('x',)); (x,) = Z._first_ngens(1)


# <your code>

```