## Project Description
This project can be break down to three parts: 1. Extended Needham Schroeder implementation 2. Reflection Attack implementation 3. CBC instead of ECB

## Environment Setup
In order to use 3DES, need pycryptodome library in python. 

In CADE run: `pip3 install pycryptodome --no-cache-dir`

## Structure of the project
1.kdc.py, alice.py, bob.py is using extended NS protocol.

2.kdc2.py, alice2.py, bob2.py, trudy.py is using original NS protocol.

3.util.py have implementations for 3DES related decryption and encryption functions.

4.extendedNS.txt show one successful authentication for extended NS protocol.

5.originalNS.txt show the output for the reflection attack

6.diffCBCAndECB.txt show the output for last two messages for CBC and ECB mode.

## Generate shared key
Generate pre shared key between Alice and KDC(K_A_KDC), and Bob and KDC(K_B_KDC) by running: `python3 generate_shared_keys.py`, it will create keys.json, so that those keys can be used accross each parties.

## 1. Extended Needham Schroeder implementation
First run: `python3 kdc.py`, then run: `python3 bob.py`, then run: `python3 alice.py`. And print the sending and receiving messages in the output. A final check about successful authentication will be shown. Ater that, manually stop kdc and bob.
(Note: for this implementation, I'm using CBC mode).

## 2. Reflection Attack implementation
For this original NS, the mode is ECB mode. In the alice2.py, I manually sleep it for 20 secs to reveal the ticket, which will be stored in stolen_data.json,  and let trudy attack.
First run: `python3 kdc2.py`, then run: `python3 bob2.py`, then run: `python3 alice2.py`, then run: `python3 trudy.py`. Bob now can accept multiple connections, the smaller number of address is alice, the larger number of address is trudy. When finish attack, manually stop kdc and bob.

## 3. CBC VS ECB
In order to use CBC mode for original NS, go to util.py, for those 2 functions, uncomment the top two lines where it says for CBC vs ECB diff. Then, repeat the steps in above task 2.
