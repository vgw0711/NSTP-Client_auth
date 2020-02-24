from passlib.hash import sha256_crypt
from passlib.hash import sha512_crypt
from passlib.hash import md5_crypt
from passlib.hash import argon2

print("1234@Vishal")

f = open("modular_crypt.txt","a")

f.write("AAAA:"+sha256_crypt.hash('1234@Vishal')+"\n")
f.write("BBBB:"+sha512_crypt.hash('1234@Vishal')+"\n")
f.write("CCCC:"+md5_crypt.hash('1234@Vishal')+"\n")
f.write("DDDD:"+argon2.hash('1234@Vishal')+"\n")

f.close()

f = open("modular_crypt.txt","r")

print(f.read())

f.close()