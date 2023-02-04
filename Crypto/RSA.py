from math import gcd
from gmpy2 import iroot
from sage.all import var, Integer, NonNegativeIntegerSemiring, Zmod, PolynomialRing, IntegerRing, ceil, floor
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from factordb.factordb import FactorDB
from .Utils import crt, ceil_int, floor_int


# input : p(int), q(int), e(int), c(int)
# output : m(int)
def simple_decrypt(p: int,q: int,e: int,c: int):
    d = pow(e, -1, (p - 1) * (q - 1))
    return pow(c, d, p * q)


# input : n(int) , n has two factor p,q and |p - q| is really small
# output : (p, q) (int, int)
def fermat_factor(n: int):
    i = 1
    while True:
        if iroot(n + i**2,2)[1]:
            a = int(iroot(n + i**2,2)[0])
            return (a + i,a - i)
        i += 1


# input : n(int) , n has a factor p that (p - 1)'s large prime factor is really small
# output : p(int) , a factor of n
def pollard_algorithm(n: int):
    a = 2
    b = 2
    while True:
        a = int(pow(a,b,n))
        p = int(gcd(a - 1,n))
        if 1 < p < n:
            return p
        b += 1


# input : e(int), c_list(list of int), n_list(list of int) , assum m^e < n1 * n2 * ... , c_list = [c1, c2, ...], n_list = [n1, n2, ...]
#         m^e ≡ c1 (mod n1)
#         m^e ≡ c2 (mod n2)
#         ...
# output : m(int)
def boardcast_attack(e: int, c_list: list, n_list: list):
    return int(iroot(crt(c_list,n_list),e)[0])


# input : n(int), e(int), c(int) , this attack assume d < (1 / 3) * (n ^ (1 / 4))
# output : m(int)
def wiener_attack(n: int, e: int, c: int):
    y = var('y')
    seq_of_continued_fraction = (Integer(e)/Integer(n)).continued_fraction()
    for i in range(2,len(seq_of_continued_fraction)):
        ci = seq_of_continued_fraction.convergent(i)
        print(ci)
        k_test = ci.numerator()
        d_test = ci.denominator()
        b = (e*d_test - 1)/k_test - n - 1
        p_test = (y**2 + b*y + n).roots()[1][0]
        if (p_test in NonNegativeIntegerSemiring()) and (n % int(p_test) == 0):
            d = int(d_test)
            break
    return int(pow(c, d, n))


# input n(int),e(int), c(int), oralce(func), r(pwn tubes)
# output m(int)
# oracle func : input : c(int), r(pwn tubes)
#               output : last_m(int) , the last bit of m
def LSB_oracle_attack(n: int, e: int, c: int, oracle, r):
    mul_const = pow(2,e,n)
    seq = [Integer(0),Integer(n),c]
    while (ceil(seq[1]) - ceil(seq[0])) > 1:
        print(ceil(seq[0]),ceil(seq[1]))
        seq[2] = (seq[2] * mul_const) % n
        last_m = oracle(seq[2],r)
        if (last_m == 1):
            seq[0] = (seq[0] + seq[1]) / 2
        else:
            seq[1] = (seq[0] + seq[1]) / 2
    return int(ceil(seq[0]))


# input : lower_bound(int), n(int), e(int), c(int), oracle(func)
# output : s(int) , this is for bleichenbacher 1998's step 2.a , step 2.b
def bleichenbacher_orifind_s(lower_bound: int, n: int, e: int, c: int, oracle):
    s = lower_bound
    while True:
        test_c = (pow(s, e, n) * c) % n
        if oracle(test_c):
            return s
        s += 1


# input : prev_s(int), M([[a1(int), b1(int)], [a2(int), b2(int)], ...]), B(int), n(int), e(int), c(int), oracle(func)
# output : s(int) , this is for bleichenbacher 1998's step 2.c
def bleichenbacher_optfind_s(prev_s: int, M, B: int, n: int, e: int, c: int, oracle):
    a = M[0][0]
    b = M[0][1]
    ri = ceil_int((b * prev_s - 2 * B) * 2, n)
    while True:
        low_bound = ceil_int(2 * B + ri * n, b)
        high_bound = ceil_int(3 * B + ri * n, a)
        for s in range(low_bound,high_bound):
            new_c = (pow(s, e, n) * c) % n
            if oracle(new_c):
                return s
        ri += 1


# input : s(int), M([[a1(int), b1(int)], [a2(int), b2(int)], ...]), B(int), n(int)
# output : M([[a1(int), b1(int)], [a2(int), b2(int)], ...]) , this is for bleichenbacher 1998's step 3
def bleichenbacher_merge_M(s: int, M, B: int, n: int):
    new_M = []
    for [a, b] in M:
        k1 = ceil_int(a * s - 3 * B + 1, n)
        k2 = floor_int(b * s - 2 * B, n) + 1
        for k in range(k1,k2):
            aa = max(a, ceil_int(2 * B + k * n, s))
            bb = min(b, floor_int(3 * B - 1 + k * n, s))
            if bb >= aa:
                new_M.append([aa, bb])
    return new_M


# input : n(int), e(int), c(int), size(int), oracle(func)
# output : m(int)
def bleichenbacher_1998(n: int, e: int, c: int, size: int, oracle):
    assert oracle(c)

    B = bytes_to_long(b'\x01' + b'\x00' * (size - 2))
    s = bleichenbacher_orifind_s(ceil_int(n, 3 * B), n, e, c, oracle)
    M = bleichenbacher_merge_M(s, [[2 * B, 3 * B - 1]], B, n)
    print(s, M)

    while True:
        if len(M) > 1:
            s = bleichenbacher_orifind_s(s + 1, n, e, c, oracle)
        else:
            if M[0][0] == M[0][1]:
                return M[0][0]
            s = bleichenbacher_optfind_s(s, M, B, n, e, c, oracle)
        M = bleichenbacher_merge_M(s, M, B, n)
        print(s, M)


# input : beta(any numeric type), delta(int, f's degree), epsilon(any numeric type, < beta / 7), n(int), f(polynomial of x mod N)
# output : smallroot(int) , root of f(x) ≡ 0 (mod b), if there's no than return -1
def coppersmith_method(beta, delta: int, epsilon, n: int, f):
    n = Integer(n)
    X = ceil(n ** (beta ** 2 / (delta) - epsilon))
    smallroot = f.small_roots(X, beta, epsilon)
    try:
        smallroot = smallroot[0]
    except:
        return -1
    return int(smallroot)


# input : mbar(int), c(int), e(int), n(int), epsilong(optional, default is 1 / Integer(8))
# output : x0(int) , m = mbar + x0
def stereotyped_message(mbar: int, c: int, e: int, n: int, epsilon = 1 / Integer(8)):
    mbar = Integer(mbar)
    c = Integer(c)
    e = Integer(e)
    n = Integer(n)

    Z = PolynomialRing(Zmod(n),implementation='NTL', names=('x',)); (x,) = Z._first_ngens(1)

    f = (mbar + x) ** e - c
    smallroot = coppersmith_method(1, e, epsilon, n, f)

    return smallroot


# input : n(int), pbar(int), epsilon (optional, default is 1 / Integer(16))
# output : (p, q) (int, int)
def known_high_bits_of_p(n: int, pbar: int, epsilon = 1 / Integer(16)):
    n = Integer(n)
    pbar = Integer(pbar)

    Z = PolynomialRing(Zmod(n),implementation='NTL', names=('x',)); (x,) = Z._first_ngens(1)

    f = pbar + x
    smallroot = coppersmith_method(1 / Integer(2), 1, epsilon, n, f)

    p = int(pbar) + smallroot
    assert (n % p == 0)
    q = int(n) // p
    return (p, q)


# input : f1(polynomial) , f2(polynomial)
# output : gcd(f1, f2) (polynomial)
def polynomialgcd(f1,f2):
    Z = PolynomialRing(IntegerRing(), names=('x',)); (x,) = Z._first_ngens(1)

    if f2 == 0:
        f1 = f1 / f1.coefficients()[-1]
        return f1

    if f2.degree() > f1.degree():
        f1, f2 = f2, f1

    diff = int(f1.degree() - f2.degree())
    coe = f1.coefficients()[-1] / f2.coefficients()[-1]
    g = f1 - f2 * coe * (x ** diff)
    return polynomialgcd(f2,g)


# input : n(int), e(int), c1(int), c2(int), f(polynomail of x mod n)
# output : m1(int) , f(m1) = m2
def franklin_reiter(n: int, e: int, c1: int, c2: int, f):
    n = Integer(n)
    e = Integer(e)
    c1 = Integer(c1)
    c2 = Integer(c2)

    Z = PolynomialRing(Zmod(n),implementation='NTL', names=('x',)); (x,) = Z._first_ngens(1)
    g1 = x ** e - c1
    g2 = f ** e - c2
    return int(-polynomialgcd(g1, g2)[0])


# input : n(int), c1(int), c2(int), e(int), epsilon(optional, default 1 / Integer(8))
# output : m1(int)
def coppersmith_short_pad_attack(n: int, c1: int, c2: int, e: int, epsilon = 1 / Integer(8)):
    n = Integer(n)
    c1 = Integer(c1)
    c2 = Integer(c2)
    ZmodN = Zmod(n)

    Z = PolynomialRing(IntegerRing(), names=('x', 'y',)); (x, y,) = Z._first_ngens(2)
    g1 = x**e - c1
    g2 = (x + y)**e - c2
    h = g1.resultant(g2,x)
    h = h.univariate_polynomial()
    h = h.change_ring(ZmodN)
    diff = h.small_roots(epsilon=epsilon)[0]

    Z = PolynomialRing(ZmodN, names=('x',)); (x,) = Z._first_ngens(1)
    f = x + diff
    m1 = franklin_reiter(n, e, c1, c2, f)

    return m1


# input : pem_filename(str)
# output : n(int), e(int)
def pem2key(pem_filename: str):
    key = RSA.importKey(open(pem_filename).read())
    return int(key.n),int(key.e)


# input : n(int)
# output : factor_list(list[int])
def factor_online(n: int):
    f = FactorDB(n)
    f.connect()
    return f.get_factor_list()
