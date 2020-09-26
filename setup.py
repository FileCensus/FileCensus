#!/usr/bin/env python3
# encoding: utf-8

from distutils.core import setup, Extension

names = ['PyABI.cpp']

names.append('sqlite3.c')

abi_module = Extension('PyABI_pyd', sources = names)

setup(name='PyABI_pyd',
      version='0.0.42',
      description='Core C++ PyABI',
      ext_modules=[abi_module])
