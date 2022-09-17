# cs42_coRSAir
[coRSAir.c](coRSAir.c) recieve as argument a public key and obtain its modulus and exponent and saved them in *coRSAir_clavepublica.txt*. It also performs the Wiener attack and obtains its private key.

## Getting started
The OpenSSL library has to be installed:
```
sudo apt-get install libssl-dev
```

## Usage
1. Create a public and a private key vulnerable to a Wiener Attack with [generador_clave_wiener.py](https://github.com/msoto5/cs42_coRSAir#other-program)
```
python3 generador_clave_wiener.py
```

2. Compile coRSAir.c with the follwing instruction:
```
gcc -o coRSAir coRSAir.c -lssl -lcrypto -lm
```

3. Run coRSAir by giving the private key created in step 1 as input:
```
./coRSAir my_pubkey.key
```

## Other program
- [generador_clave_wiener.py](generador_clave_wiener.py) creates a private key that is vulnurable to Wiener attack. The key generated is small so, the program runs faster and numbers can be treated with long long int data types. The private key generated

### Instructions
Before running, the following libraries have to be installed:
- gmpy2:
```
pip install gmpy2
```
- Pycrypto:
```
pip install pycrypto
```