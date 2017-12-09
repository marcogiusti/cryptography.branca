# Copyright (c) 2017 Marco Giusti
# See LICENCE for details.

'''
cryptography.branca is a thin layer on top of cryptography.fernet that
uses passwords and not keys as secret.

The use is all in all similar to Fernet:

>>> from branca import Branca
>>> pwd = b'qwerty'
>>> b = Branca(pwd)
>>> token = b.encrypt(b'my deep dark secret')
>>> b.decrypt(token)
b'my deep dark secret'
>>>

The use of MultiBranca is also very similar to MultiFernet. Pay
attention that MultiBranca has not ``encrypt`` method.

>>> from branca import Branca, MultiBranca
>>> key1 = Branca(b'qwerty')
>>> key2 = Branca(b'password')
>>> token = key2.encrypt(b'Secret message!')
>>> b = MultiBranca([key1, key2])
>>> b.decrypt(token)
b'Secret message!'
>>>
'''

import base64
import os
import struct
from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


__all__ = [
    '__version__', 'Branca', 'MultiBranca', 'InvalidToken', 'InvalidKey',
    'MIN_HASH_ITERATIONS'
]
__version__ = '0.1'


MIN_HASH_ITERATIONS = 100000


class Branca:

    def __init__(self, password):
        self._pwd = password
        self._backend = default_backend()

    def _build_kdf(self, salt, iterations):
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self._backend
        )

    def encrypt(self, data):
        salt = os.urandom(32)
        iterations = MIN_HASH_ITERATIONS
        kdf = self._build_kdf(salt, iterations)
        derived_key = kdf.derive(self._pwd)
        h = hashes.Hash(hashes.SHA256(), self._backend)
        h.update(derived_key)
        key = base64.urlsafe_b64encode(derived_key)
        parts = (
            b'\x80' +
            salt +
            struct.pack("<I", iterations) +
            h.finalize() +
            Fernet(key).encrypt(data)
        )
        return parts

    def decrypt(self, token, ttl=None):
        if not token or token[0] != 0x80:
            raise InvalidToken
        salt = token[1:33]
        try:
            iterations, = struct.unpack("<I", token[33:37])
        except struct.error:
            raise InvalidToken
        kdf = self._build_kdf(salt, iterations)
        derived_key = kdf.derive(self._pwd)
        h = hashes.Hash(hashes.SHA256(), self._backend)
        h.update(derived_key)
        if not constant_time.bytes_eq(h.finalize(), token[37:69]):
            raise InvalidKey("Keys do not match.")
        key = base64.urlsafe_b64encode(derived_key)
        return Fernet(key).decrypt(token[69:], ttl)


class MultiBranca:

    def __init__(self, brancas):
        brancas = list(brancas)
        if not brancas:
            raise ValueError(
                "MultiBranca requires at least one Branca instance"
            )
        self._brancas = brancas

    def decrypt(self, msg, ttl=None):
        for b in self._brancas:
            try:
                return b.decrypt(msg, ttl)
            except InvalidKey:
                pass
        raise InvalidKey("Keys do not match.")
