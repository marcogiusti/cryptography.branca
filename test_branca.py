# Copyright (c) 2017 Marco Giusti
# See LICENCE for details.

import pickle
import unittest
import branca


DATA = b'asdfasdfsadf'
# reduce the default number of iterations to drammatically speed up the tests
branca.MIN_HASH_ITERATIONS = 100


class TestBranca(unittest.TestCase):

    def test_simple_roundtrip(self):
        b = branca.Branca(b'pwd')
        self.assertEqual(b.decrypt(b.encrypt(DATA)), DATA)

    def test_invalid_token(self):
        b = branca.Branca(b'pwd')
        token = b.encrypt(DATA)
        new_token = b'\x81' + token[1:]
        self.assertRaises(branca.InvalidToken, b.decrypt, new_token)

    def test_invalid_password(self):
        b = branca.Branca(b'pwd')
        token = b.encrypt(DATA)
        b2 = branca.Branca(b'pwd2')
        self.assertRaises(branca.InvalidKey, b2.decrypt, token)

    def test_short_token(self):
        b = branca.Branca(b'pwd')
        token = b.encrypt(DATA)
        self.assertRaises(branca.InvalidToken, b.decrypt, token[:36])


class TestMultiBranca(unittest.TestCase):

    def test_no_brancas(self):
        self.assertRaises(ValueError, branca.MultiBranca, ())

    def test_one_valid_branca(self):
        b = branca.Branca(b'pwd')
        mb = branca.MultiBranca([b])
        token = b.encrypt(DATA)
        self.assertEqual(mb.decrypt(token), DATA)

    def test_second_valid_branca(self):
        b1 = branca.Branca(b'pwd1')
        b2 = branca.Branca(b'pwd2')
        mb = branca.MultiBranca([b1, b2])
        token = b2.encrypt(DATA)
        self.assertEqual(mb.decrypt(token), DATA)

    def test_invalid_branca(self):
        b1 = branca.Branca(b'pwd1')
        b2 = branca.Branca(b'pwd2')
        b3 = branca.Branca(b'pwd3')
        mb = branca.MultiBranca([b1, b2])
        token = b3.encrypt(DATA)
        self.assertRaises(branca.InvalidKey, mb.decrypt, token)

    def test_multi_decrypt(self):
        DATA1 = b'data1'
        DATA2 = b'data2'
        b1 = branca.Branca(b'pwd1')
        b2 = branca.Branca(b'pwd2')
        mb = branca.MultiBranca([b1, b2])
        token1 = b1.encrypt(DATA1)
        token2 = b2.encrypt(DATA2)
        self.assertEqual(mb.decrypt(token1), DATA1)
        self.assertEqual(mb.decrypt(token2), DATA2)

    def test_branca_double(self):
        DATA1 = b'data1'
        DATA2 = b'data2'
        pwd1 = branca.Fernet.generate_key()
        pwd2 = branca.Fernet.generate_key()
        #
        token1 = branca.Branca(pwd1).encrypt(DATA1)
        token2 = branca.Branca(pwd2).encrypt(DATA2)
        b = branca.Branca(b'pwd')
        sensible_data = pickle.dumps([pwd1, pwd2])
        token3 = b.encrypt(sensible_data)
        #
        mb = branca.MultiBranca.from_token(token3, b'pwd', pickle.loads)
        self.assertEqual(mb.decrypt(token1), DATA1)
        self.assertEqual(mb.decrypt(token2), DATA2)
