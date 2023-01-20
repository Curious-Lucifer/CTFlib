from math import gcd
from functools import reduce

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
