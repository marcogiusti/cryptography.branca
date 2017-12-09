# Copyright (c) 2017 Marco Giusti
# See LICENCE for details.

from setuptools import setup


setup(
    name='cryptography.branca',
    version='0.1',
    description='Encryption facilities on top of cryptography.fernet',
    long_description=open('README').read(),
    author='Marco Giusti',
    author_email='marco.giusti@posteo.de',
    url='https://github.com/marcogiusti/cryptography.branca',
    license='MIT',
    py_modules=['branca', 'test_branca'],
    install_requires=[
        'cryptography'
    ]
)
