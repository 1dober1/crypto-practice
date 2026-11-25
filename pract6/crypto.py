"""Учебные алгоритмы. Модуль использует только встроенные операции Python."""

MASK = (1 << 32) - 1
SHA_INITIAL = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)
SHA_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


def rotate(x, count):
    return ((x >> count) | (x << (32 - count))) & MASK


def sha256(data):
    state = list(SHA_INITIAL)
    padded = data + b'\x80' + bytes((55 - len(data)) % 64) + (8 * len(data)).to_bytes(8, 'big')
    for offset in range(0, len(padded), 64):
        w = [int.from_bytes(padded[i:i + 4], 'big') for i in range(offset, offset + 64, 4)]
        for i in range(16, 64):
            x, y = w[i - 15], w[i - 2]
            s0 = rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3)
            s1 = rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)
        a, b, c, d, e, f, g, h = state
        for constant, word in zip(SHA_K, w):
            t1 = h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) + ((e & f) ^ (~e & g)) + constant + word
            t2 = (rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
            a, b, c, d, e, f, g, h = (t1 + t2) & MASK, a, b, c, (d + t1) & MASK, e, f, g
        state = [(x + y) & MASK for x, y in zip(state, (a, b, c, d, e, f, g, h))]
    return b''.join(x.to_bytes(4, 'big') for x in state)


class Generator:
    def __init__(self, seed):
        self.key = sha256(b'pract6-seed\0' + seed)
        self.counter = 0

    def bytes(self, size):
        output = bytearray()
        while len(output) < size:
            output.extend(sha256(self.key + self.counter.to_bytes(16, 'big')))
            self.counter += 1
        return bytes(output[:size])

    def bits(self, count):
        return int.from_bytes(self.bytes((count + 7) // 8), 'big') & ((1 << count) - 1)

    def below(self, limit):
        if limit < 1:
            raise ValueError('Верхняя граница должна быть положительной.')
        while True:
            candidate = self.bits((limit - 1).bit_length())
            if candidate < limit:
                return candidate


def miller_rabin(n, rng, rounds=32):
    if n < 4 or n % 2 == 0:
        return n in (2, 3)
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + rng.below(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def jacobi(a, n):
    sign = 1
    a %= n
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                sign = -sign
        if a % 4 == n % 4 == 3:
            sign = -sign
        a, n = n % a, a
    return sign if n == 1 else 0


def solovay_strassen(n, rng, rounds=16):
    if n < 4 or n % 2 == 0:
        return n in (2, 3)
    for _ in range(rounds):
        a = 2 + rng.below(n - 3)
        symbol = jacobi(a, n)
        if symbol == 0 or pow(a, (n - 1) // 2, n) != symbol % n:
            return False
    return True


SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)


def probable_prime(n, rng):
    if n in SMALL_PRIMES:
        return True
    return all(n % p for p in SMALL_PRIMES) and miller_rabin(n, rng) and solovay_strassen(n, rng)


def prime_steps(bits, rng, blum=False):
    while True:
        # Два верхних бита обеспечивают полную длину произведения двух ключевых простых.
        n = rng.bits(bits) | (3 << (bits - 2)) | (3 if blum else 1)
        if probable_prime(n, rng):
            return n
        yield


def gm_key_steps(rng, bits=1024):
    p = yield from prime_steps(bits, rng, blum=True)
    while True:
        q = yield from prime_steps(bits, rng, blum=True)
        if q != p:
            return p, q


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def encrypt_steps(data, n, rng):
    width = (n.bit_length() + 7) // 8
    packet = bytearray()
    for byte in data:
        for shift in range(7, -1, -1):
            while True:
                r = 1 + rng.below(n - 1)
                if gcd(r, n) == 1:
                    break
            square = r * r % n
            c = n - square if (byte >> shift) & 1 else square
            packet.extend(c.to_bytes(width, 'big'))
        yield
    return bytes(packet)


def decrypt_steps(packet, private):
    p, q = private
    n = p * q
    width = (n.bit_length() + 7) // 8
    if len(packet) % (8 * width):
        raise ValueError('Неверная длина шифротекста.')
    output = bytearray()
    for start in range(0, len(packet), 8 * width):
        byte = 0
        for i in range(start, start + 8 * width, width):
            c = int.from_bytes(packet[i:i + width], 'big')
            if not 0 < c < n or gcd(c, n) != 1:
                raise ValueError('Повреждён блок шифротекста.')
            bit = pow(c, (p - 1) // 2, p) == p - 1
            byte = (byte << 1) | bit
        output.append(byte)
        yield
    return bytes(output)


HORS_T = 4096
HORS_K = 16


def hors_key_steps(rng):
    secret, public = [], []
    for i in range(HORS_T):
        value = rng.bytes(32)
        secret.append(value)
        public.append(sha256(value))
        if i % 32 == 31:
            yield
    return HorsKey(secret, tuple(public))


def hors_indices(message):
    prefix = int.from_bytes(sha256(message)[:24], 'big')
    return [(prefix >> shift) & 0xfff for shift in range(180, -1, -12)]


class HorsKey:
    def __init__(self, secret, public):
        self.secret = secret
        self.public = public

    def sign(self, message):
        if self.secret is None:
            raise ValueError('Этот ключ HORS уже использован. Создайте и передайте новый.')
        signature = b''.join(self.secret[i] for i in hors_indices(message))
        self.secret = None
        return signature


def verify(message, signature, public):
    if len(public) != HORS_T or len(signature) != 32 * HORS_K:
        return False
    return all(sha256(signature[j * 32:(j + 1) * 32]) == public[i]
               for j, i in enumerate(hors_indices(message)))
