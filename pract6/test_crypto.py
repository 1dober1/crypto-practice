import unittest

from crypto import (Generator, decrypt_steps, encrypt_steps, gm_key_steps, hors_key_steps, jacobi, miller_rabin,
                    sha256, solovay_strassen, verify)


def complete(steps):
    try:
        while True:
            next(steps)
    except StopIteration as result:
        return result.value


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.rng = Generator(b'fixed seed for tests')

    def test_sha256_vectors(self):
        vectors = (
            (b'', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
            (b'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
            (b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
             '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'),
        )
        for message, expected in vectors:
            self.assertEqual(sha256(message).hex(), expected)

    def test_generator(self):
        first = self.rng.bytes(80)
        self.assertEqual(first, Generator(b'fixed seed for tests').bytes(80))
        self.assertNotEqual(first, self.rng.bytes(80))
        self.assertNotEqual(first, Generator(b'another seed').bytes(80))
        self.assertEqual(self.rng.below(1), 0)
        self.assertEqual({self.rng.below(7) for _ in range(100)}, set(range(7)))
        self.assertTrue(0 <= self.rng.bits(1024) < (1 << 1024))

    def test_primality(self):
        for check in (miller_rabin, solovay_strassen):
            for n in (-3, 0, 1, 4, 9, 341, 561, 1105, 1729, 45561, (2**127 - 1)**2):
                self.assertFalse(check(n, self.rng), (check.__name__, n))
            for n in (2, 3, 5, 7, 65537, 2**127 - 1):
                self.assertTrue(check(n, self.rng), (check.__name__, n))

    def test_jacobi(self):
        for a, n, expected in ((2, 7, 1), (3, 7, -1), (7, 21, 0), (2, 15, 1), (3, 17, -1)):
            self.assertEqual(jacobi(a, n), expected)

    def test_gm_roundtrip_full_size(self):
        p, q = complete(gm_key_steps(self.rng))
        self.assertNotEqual(p, q)
        self.assertEqual((p.bit_length(), q.bit_length(), (p*q).bit_length()), (1024, 1024, 2048))
        self.assertEqual((p % 4, q % 4), (3, 3))
        data = '\x00Привет 🔑'.encode()
        ciphertext = complete(encrypt_steps(data, p*q, self.rng))
        self.assertEqual(len(ciphertext), 8 * 256 * len(data))
        self.assertNotEqual(ciphertext, complete(encrypt_steps(data, p*q, self.rng)))
        self.assertEqual(complete(decrypt_steps(ciphertext, (p, q))), data)

    def test_gm_known_blocks(self):
        # Квадрат 2² кодирует ноль, его отрицание по модулю 77 кодирует единицу.
        self.assertEqual(complete(decrypt_steps(bytes([4, 73] * 4), (7, 11))), b'U')
        for packet in (b'x', bytes(8), bytes([7] * 8), bytes([77] * 8)):
            with self.assertRaises(ValueError):
                complete(decrypt_steps(packet, (7, 11)))

    def test_hors(self):
        key = complete(hors_key_steps(self.rng))
        sig = key.sign(b'packet')
        self.assertEqual(len(sig), 512)
        self.assertTrue(verify(b'packet', sig, key.public))
        self.assertFalse(verify(b'Packet', sig, key.public))
        self.assertFalse(verify(b'packet', bytes([sig[0] ^ 1]) + sig[1:], key.public))
        self.assertFalse(verify(b'packet', sig[:-1], key.public))
        self.assertFalse(verify(b'packet', sig, key.public[1:] + key.public[:1]))
        with self.assertRaises(ValueError):
            key.sign(b'next packet')


if __name__ == '__main__':
    unittest.main()
