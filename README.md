# cs42_coRSAir
[coRSAir.c](coRSAir.c) recieve as argument a public key and obtain its modulus and exponent and saved them in *coRSAir_clavepublica.txt*. It also performs the Wienner attack and obtains its private key.

## Other program
- [generador_clave_wiener.py](generador_clave_wiener.py) creates a private key that is vulnurable to Wiener attack. The key generated is small so, the program runs faster and numbers can be treated with long long int data types. The private key generated

### Instructions
Install the following libraries:
- gmpy2:
```
pip install gmpy2
```
- Pycrypto:
```
pip install pycrypto
```



## Getting started
The OpenSSL library has to be installed:
```
sudo apt-get install libssl-dev
```

## Usage
The following instruction was used to compile coRSAir.c:


## Examples