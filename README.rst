.. image:: https://travis-ci.org/kyuupichan/electrumx.svg?branch=master
    :target: https://travis-ci.org/kyuupichan/electrumx
.. image:: https://coveralls.io/repos/github/kyuupichan/electrumx/badge.svg
    :target: https://coveralls.io/github/kyuupichan/electrumx

===============================================
ElectrumX - Reimplementation of electrum-server
===============================================

For a future network with bigger blocks.

  :Licence: MIT
  :Language: Python (>= 3.6)
  :Author: Neil Booth

Documentation
=============

See `readthedocs <https://electrumx.readthedocs.io/>`_.

Instructions
=============

Environmental Variables Required
==========
- DB_DIRECTORY = ~/db_directory   # or any custom dir
- DAEMON_URL = RPC_USER:RPC_PASS@RPC_HOST:RPC_PORT/
- COIN = Ocean
- NET = testnet   # or mainnet

Unit Testing
=============
- pip3 install x11_hash tribus_hash quark_hash xevan_hash groestlcoin_hash blake256
- pip3 install pytest
- pytest

Running the server
=============
- brew install leveldb
- python3 setup.py build
- python3 setup.py install
- ./electrumx_server
