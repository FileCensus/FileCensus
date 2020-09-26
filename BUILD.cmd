@echo off
del build\*.* /F /Q /S
python3 setup.py clean
python3 setup.py install
python3 smoke_0.py
python3 smoke_1.py
