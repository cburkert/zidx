from setuptools import (
    setup,
    find_packages,
)


def readme():
    with open('README.rst') as f:
        return f.read()


setup(
    name='zidx',
    version='0.0.1',
    description='Implementation of secure indexing scheme by Goh',
    long_description=readme(),
    author='Christian Burkert',
    url='https://github.com/cburkert/zidx',
    packages=find_packages(),
    install_requires=[
        'BitVector',
    ],
)
