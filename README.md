# trinity
code of trinity 
[Global Description]
Multithreading support can be enabled in the til/globalic_param. h file to improve SHVE computation speed.

【 Source Information 】
SHVE C++is derived from
https://github.com/MonashCybersecurityLab/SHVE

QF comes from
https://github.com/vedantk/quotient-filter


[Dependency Library Installation]
Libraries that need to be relied upon. Static libraries are faster.
openssl
NTL
gmp



[gmp]
Install dependency library m4
sudo apt install m4

Execute in GMP root directory
./configure CXXFLAGS=-fPIC
make
sudo make install
sudo ldconfig



[NTL]
Execute in the NTL/src directory
./configure CXXFLAGS=-fPIC
make
sudo make install
