from functools import reduce


# input : a(bytes), b(bytes), ...
# output : these bytes' xor(bytes)
def xor(*args):
    return bytes([reduce(lambda i, j : i ^ j, l) for l in zip(*args)])


# input : a(int), b(int)
# output : ceil(a / b) (int)
def ceil_int(a: int, b: int):
    return (a // b) + (a % b > 0)


# input : a(int), b(int)
# output : floor(a / b) (int)
def floor_int(a: int, b: int):
    return a // b


# input : a(int), b(int) (a > 0 and b > 0)
# output : (x, y) (int, int) that satisfy ax + by = gcd(a,b)
def extended_gcd(a: int,b: int):
    assert (a > 0) and (b > 0)

    q = a // b
    r = a % b
    if (b % r) == 0:
        return 1,-q
    x,y = extended_gcd(b,r)
    return y,(x - q*y)


# input : a_list(list of int), m_list(list of int) , and assume a_list = [a1, a2, ...], m_list = [m1 ,m2, ...]
#         x ≡ a1 (mod m1)
#         x ≡ a2 (mod m2)
#         ...
# output : x % M (int) , M = m1 * m2 * ...
def crt(a_list: list, m_list: list):
    assert len(a_list) == len(m_list)

    M = reduce(lambda x, y : x * y, m_list)
    Mi_list = [M // m for m in m_list]
    ti_list = [pow(i[0],-1,i[1]) for i in zip(Mi_list,m_list)]
    return sum([i[0] * i[1] * i[2] for i in zip(a_list,ti_list,Mi_list)]) % M


# input : value(int), shift(int)
# output : result(int) , value = (result >> shift) ^ result
def un_bitshift_right_xor(value: int, shift: int):
    i = 0
    result = 0
    while ((i * shift) < 32):
        partmask = int('1' * shift + '0' * (32 - shift), base = 2) >> (shift * i)
        part = value & partmask
        value ^= (part >> shift)
        result |= part
        i += 1
    return result


# input : value(int), shift(int), mask(int)
# output : result(int) , value = ((result << shift) & mask) ^ result
def un_bitshift_left_xor_mask(value: int, shift: int, mask: int):
    i = 0
    result = 0
    while ((i * shift) < 32):
        partmask = int('0' * (32 - shift) + '1' * shift, base = 2) << (shift * i)
        part = value & partmask
        value ^= (part << shift) & mask
        result |= part
        i += 1
    return result

