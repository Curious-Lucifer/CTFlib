from sage.all import var, GF, PolynomialRing
from Crypto.Util.number import bytes_to_long, long_to_bytes
from .Utils import xor


# input : flag_length(int), oracle(func), r(pwn tubes)
# output : flag(bytes)
# oracle func : input : plain(bytes), r(pwn tubes)
#               output : cipher(bytes) , cipher of (plain + flag)
def prepend_oracle_attack(flag_length: int, oracle, r):
    flag_enc_list = [oracle(b'a' * i, r) for i in reversed(range(16))]
    flag = b'a' * 16
    for i in range(flag_length):
        right_block_enc = flag_enc_list[i % 16][(i // 16) * 16:(i // 16 + 1) * 16]
        for j in range(256):
            if oracle(flag[-15:] + bytes([j]), r)[:16] == right_block_enc:
                flag += bytes([j])
                break
        print(str(flag[16:]), end='\r')
    print(f'result : {str(flag[16:])}')

    return flag[16:]


# input : pre_cipher_block(bytes), cipher_block(bytes), oracle(func), r(pwn tubes)
# output : plain_block(bytes) , cipher_block's plain
# oracle func : input : cipher(bytes), r(pwn tubes)
#               output : padding_right(bool) , if padding of cipher's plain is right, then output True, else False
def padding_oracle_attack(pre_cipher_block: bytes, cipher_block: bytes, oracle, r):
    assert len(pre_cipher_block) == len(cipher_block) == 16

    last_bytes = []
    for i in range(256):
        cipher_test = pre_cipher_block[:15] + bytes([i]) + cipher_block
        if oracle(cipher_test, r):
            last_bytes.append(bytes([i]))
    if len(last_bytes) == 1:
        plain_block = xor(last_bytes[0], b'\x01', pre_cipher_block[-1:])
    else:
        plain_block = xor(last_bytes[last_bytes.index(pre_cipher_block[-1:]) ^ 1], b'\x01', pre_cipher_block[-1:])

    print(str(plain_block), end='\r')
    for j in range(1,16):
        for i in range(256):
            cipher_test = pre_cipher_block[:15 - j] + bytes([i]) + xor(pre_cipher_block[-j:], plain_block, bytes([j + 1]) * j) + cipher_block
            if oracle(cipher_test, r):
                plain_block = xor(bytes([i]), bytes([j + 1]), pre_cipher_block[-j - 1:-j]) + plain_block
                break
        print(str(plain_block), end='\r')
    print(f'result : {str(plain_block)}')

    return plain_block


class GCM_Forbidden_Attack:
    # input : AAD_list (list[bytes], [AAD1, AAD2, ...]) , 
    #         cipher_list (list[bytes], [cipher1, cipher2, ...])
    #         auth_tag_list (list[bytes], [auth_tag1, auth_tag2, ...])
    def __init__(self, AAD_list, cipher_list, auth_tag_list):
        assert len(AAD_list) == len(cipher_list) == len(auth_tag_list)

        self.AAD_list = AAD_list
        self.cipher_list = cipher_list
        self.auth_tag_list = auth_tag_list

        x = var('x')
        K = GF(2 ** 128 , name = 'a', modulus = x ** 128  + x ** 7  + x ** 2  + x + 1 , names=('a',))
        (self.a,) = K._first_ngens(1)
        Z = PolynomialRing(K, names=('x',))
        (self.x,) = Z._first_ngens(1)


    # input : bytes_string (bytes, 16 bytes)
    # output : poly (polynomial of 'a' that in GF(2 ** 128, name = 'a', modulus = x ** 128 + x ** 7 + x ** 2 + x + 1))
    def bytes2poly(self, bytes_string: bytes):
        assert len(bytes_string) == 16

        bin_bytes_string = bin(bytes_to_long(bytes_string))[2:].rjust(128, '0')
        return sum([int(bin_bytes_string[i]) * (self.a ** i) for i in range(len(bin_bytes_string))])


    # input : polynomial (polynomial of 'a' that in GF(2 ** 128, name = 'a', modulus = x ** 128 + x ** 7 + x ** 2 + x + 1))
    # output : bytes_string (bytes, 16 bytes)
    def poly2bytes(self, polynomial):
        term_list = str(polynomial).split(' + ')
        bin_list = ['0'] * 128

        if '1' in term_list:
            bin_list[0] = '1'
            term_list.pop(-1)

        if 'a' in term_list:
            bin_list[1] = '1'
            term_list.pop(-1)

        for term in term_list:
            bin_list[int(term.split('^')[1])] = '1'

        return long_to_bytes(int(''.join(bin_list), base = 2), 16)


    # input : AAD(bytes), cipher(bytes), auth_tag(bytes)
    def append_new(self, AAD: bytes, cipher: bytes, auth_tag: bytes):
        self.AAD_list.append(AAD)
        self.cipher_list.append(cipher)
        self.auth_tag_list.append(auth_tag)


    # input : none
    # output : H_list (list[bytes], [H1, H2, ...] and one of it is the real H)
    def get_H(self):
        H_list = set()
        for i in range(len(self.cipher_list) - 1):
            payload1 = self.AAD_list[i]
            if (len(payload1) % 16) != 0:
                payload1 += b'\x00' * (16 - len(payload1) % 16)
            payload1 += self.cipher_list[i]
            if (len(payload1) % 16) != 0:
                payload1 += b'\x00' * (16 - len(payload1) % 16)
            payload1 += long_to_bytes(len(self.AAD_list[i]) * 8, 8) + long_to_bytes(len(self.cipher_list[i]) * 8, 8)

            payload2 = self.AAD_list[i + 1]
            if (len(payload2) % 16) != 0:
                payload2 += b'\x00' * (16 - len(payload2) % 16)
            payload2 += self.cipher_list[i + 1]
            if (len(payload2) % 16) != 0:
                payload2 += b'\x00' * (16 - len(payload2) % 16)
            payload2 += long_to_bytes(len(self.AAD_list[i + 1]) * 8, 8) + long_to_bytes(len(self.cipher_list[i + 1]) * 8, 8)

            poly1 = sum([self.bytes2poly(payload1[j * 16:(j + 1) * 16]) * (self.x ** (len(payload1) // 16 - j)) for j in range(len(payload1) // 16)])
            poly2 = sum([self.bytes2poly(payload2[j * 16:(j + 1) * 16]) * (self.x ** (len(payload2) // 16 - j)) for j in range(len(payload2) // 16)])

            f = poly1 - poly2 + self.bytes2poly(self.auth_tag_list[i + 1]) - self.bytes2poly(self.auth_tag_list[i])
            root_list = [self.poly2bytes(root) for (root, _) in f.roots()]

            if i == 0:
                H_list = set(root_list)
            else:
                H_list &= set(root_list)
        
        return list(H_list)


    # input : H_list (list[bytes], [H1, H2, ...] and one of it is the real H)
    # output : EJ0_list (list[bytes], [EJ0_1, EJ0_2, ...] corresponding to H_list)
    def get_EJ0(self, H_list):
        payload = self.AAD_list[0]
        if (len(payload) % 16) != 0:
            payload += b'\x00' * (16 - len(payload) % 16)
        payload += self.cipher_list[0]
        if (len(payload) % 16) != 0:
            payload += b'\x00' * (16 - len(payload) % 16)
        payload += long_to_bytes(len(self.AAD_list[0]) * 8, 8) + long_to_bytes(len(self.cipher_list[0]) * 8, 8)

        EJ0_list = []
        for H in H_list:
            EJ0 = self.bytes2poly(self.auth_tag_list[0]) - sum([self.bytes2poly(payload[j * 16:(j + 1) * 16]) * (self.bytes2poly(H) ** (len(payload) // 16 - j)) for j in range(len(payload) // 16)])
            EJ0_list.append(self.poly2bytes(EJ0))

        return EJ0_list


    # input : H(bytes), EJ0(bytes), AAD(bytes), cipher(bytes)
    # output : auth_tag(bytes) , cipher's auth_tag
    def gen_auth_tag(self, H: bytes, EJ0: bytes, AAD: bytes, cipher: bytes):
        payload = AAD
        if (len(payload) % 16) != 0:
            payload += b'\x00' * (16 - len(payload) % 16)
        payload += cipher
        if (len(payload) % 16) != 0:
            payload += b'\x00' * (16 - len(payload) % 16)
        payload += long_to_bytes(len(AAD) * 8, 8) + long_to_bytes(len(cipher) * 8, 8)

        auth_tag_poly = sum([self.bytes2poly(payload[j * 16:(j + 1) * 16]) * (self.bytes2poly(H) ** (len(payload) // 16 - j)) for j in range(len(payload) // 16)])
        auth_tag_poly += self.bytes2poly(EJ0)

        return self.poly2bytes(auth_tag_poly)