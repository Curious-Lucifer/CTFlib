from math import gcd
from functools import reduce
from .Utils import un_bitshift_right_xor, un_bitshift_left_xor_mask

# input : state(list[int]) , that state[i] = (state[i - 1] * m + inc) % N
# output : m(int), inc(int), N(int)
def LCG_attack(state):
    diff_list = [s1 - s0 for s0, s1 in zip(state, state[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diff_list, diff_list[1:], diff_list[2:])]
    N = abs(reduce(gcd, zeroes))

    m = (diff_list[1] * pow(diff_list[0], -1, N)) % N
    inc = (state[1] - state[0] * m) % N

    return int(m), int(inc), N


# input : seed(int), m(int), inc(int), N(int), num(int)
# output : s(int) , seed = state[0] , s = state[n]
def LCG_generate(seed: int, m: int, inc: int, N: int, num: int):
    s = seed
    for _ in range(num):
        s = (m * s + inc) % N
    
    return s


# input : value(int)
# output : value(int) , for MT19937
def rand_to_state(value: int):
    value = un_bitshift_right_xor(value, 18)
    value = un_bitshift_left_xor_mask(value, 15, 0xefc60000)
    value = un_bitshift_left_xor_mask(value, 7, 0x9d2c5680)
    value = un_bitshift_right_xor(value, 11)
    return value


# input : value(int)
# output : value(int) , for MT19937
def state_to_rand(value: int):
    value ^= (value >> 11)
    value ^= (value << 7) & 0x9d2c5680
    value ^= (value << 15) & 0xefc60000
    value ^= (value >> 18)
    return value


# input : state(list[int])
# output : next_state(list[int]) , next state of list
def gen_next_state(state):
    assert len(state) == 624
    for i in range(624):
        y = (state[i] & 0x80000000) + (state[(i + 1) % 624] & 0x7fffffff)
        next = y >> 1
        next ^= state[(i + 397) % 624]
        if ((y & 1) == 1):
            next ^= 0x9908b0df
        state[i] = next


# input : rand_list(list[int]), n(int) , rand_list is the first 624's 32 bits random number's list
# output : random_num(int) , the n's random number , if n == 0, random_num = rand_list[0]
def MT19937_attack(rand_list, n: int):
    if n < 624:
        return rand_list[n]

    state = [rand_to_state(r) for r in rand_list]
    for _ in range(n // 624):
        gen_next_state(state)

    return state_to_rand(state[n % 624])
