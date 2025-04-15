---
title: nex4.11-4.13wp
published: 2025-04-15
description: '清明假期出去玩了，回来继续做题'
image: ''
tags: [RSA,NTRU,lattice,mt19937,Matirx]
category: 'ctf'
draft: false 
lang: ''
---
# nex4.11-4.13wp

# Crypto
## 1.<font style="color:rgba(0, 0, 0, 0.88);">Really RSA 5</font>
  
四元数RSA,我们知道phi=p^2-1(大概，这题使用这个是可行的),注意到gcd(e,phi)=3!=1,所以不能直接求出m的值

分解e=40716873=3^2*4524097,求d_0=inverse(e//9,phi),求m_0=pow(c,d_0,p)

$ m^e\equiv c\pmod{p} \\
m^{\frac{e}{9}\cdot9}\equiv c\pmod{p} \\
c^{d_0}\equiv (m^{\frac{e}{9}\cdot d_0})^9\pmod{p} \\
\because \frac{e}{9}\cdot d_0\equiv1\pmod{\phi} \\
\therefore m_0\equiv m^9 \pmod{p}
 $

学长提示还能往下化,我们继续推导

[一次同余方程](https://math.fandom.com/zh/wiki/%E4%B8%80%E6%AC%A1%E5%90%8C%E4%BD%99%E6%96%B9%E7%A8%8B)

$ \because \gcd(9,\phi)|3\\
\therefore 9x\equiv3\pmod{\phi}有解 \\
所以我们可以找到一个x,令\\
{m_0}^x\equiv m^{3}\pmod{p} \\ $

最后我们得到了m^3,接下来就是有限域内求四元数的三次根，我刚开始认为可能是要自己推导什么，结果学长说可以直接sage解方程(太强了sagemath)，那我们直接把(a+bi+ci+di)^3展开，和我们得到的m^3对比系数解有限域下的方程组得到三组解，得到flag

解题脚本

```python
from Crypto.Util.number import *
from sage.all import *

class ComComComComplex:
    def __init__(self, value=[0,0,0,0]):
        self.value = value
    def __str__(self):
        s = str(self.value[0])
        for k,i in enumerate(self.value[1:]):
            if i >= 0:
                s += '+'
            s += str(i) + 'ijk'[k]
        return s
    def __add__(self, x):
        return ComComComComplex([i+j for i,j in zip(self.value, x.value)])
    def __mul__(self, x):
        a = self.value[0]*x.value[0] - self.value[1]*x.value[1] - self.value[2]*x.value[2] - self.value[3]*x.value[3]
        b = self.value[0]*x.value[1] + self.value[1]*x.value[0] + self.value[2]*x.value[3] - self.value[3]*x.value[2]
        c = self.value[0]*x.value[2] - self.value[1]*x.value[3] + self.value[2]*x.value[0] + self.value[3]*x.value[1]
        d = self.value[0]*x.value[3] + self.value[1]*x.value[2] - self.value[2]*x.value[1] + self.value[3]*x.value[0]
        return ComComComComplex([a,b,c,d])
    def __mod__(self, x):
        return ComComComComplex([i % x for i in self.value])
    def __pow__(self, x, n=None):
        tmp = ComComComComplex(self.value)
        a = ComComComComplex([1,0,0,0])
        while x:
            if x & 1:
                a *= tmp
            tmp *= tmp
            if n:
                a %= n
                tmp %= n
            x >>= 1
        return a

e = 40716873
p = 91518581093691360767792784582630168525478221031706879077746392024796315797173
c = ComComComComplex([27433389502395453725899338833004533886973035074136307407390094566911519798866,
                     61569532542060261432143754809950005548158824698595807553935486806698931022648,
                     17936840409307100393467976341375653546372779107111111673721565775819780552166,
                     87685620526500044941824099984199162386702300192762777453002915151143238662203])

phi = p**2 - 1
d_0= inverse(e//9, phi)
m = pow(c, d_0, p)
x = (phi + 3) // 9
m = pow(m, x, p)
x1, x2, x3, x4 = m.value

F = GF(p)
R.<a,b,c,d> = PolynomialRing(F, order='lex')

eq1 = a^3 - F(3)*a*(b^2 + c^2 + d^2) - F(x1)
eq2 = b*(F(3)*a^2 - (b^2 + c^2 + d^2)) - F(x2)
eq3 = c*(F(3)*a^2 - (b^2 + c^2 + d^2)) - F(x3)
eq4 = d*(F(3)*a^2 - (b^2 + c^2 + d^2)) - F(x4)

I = R.ideal([eq1, eq2, eq3, eq4])
B = I.groebner_basis()
solutions = I.variety()
for i in range(len(solutions)):
    flag=b''
    flag+=long_to_bytes(solutions[i][a].lift())
    flag+=long_to_bytes(solutions[i][b].lift())
    flag+=long_to_bytes(solutions[i][c].lift())
    flag+=long_to_bytes(solutions[i][d].lift())
    print(flag)
```

> nex{C0McOMC0McOmp1EX_A5_EAsy_45_C0MPLEX}
>

## 2.<font style="color:rgba(0, 0, 0, 0.88);">NTR警告</font>
完全标准的ntru加密，参数选择过小，直接构造格就可以解出私钥，然后解出key后，用aes解密得到flag(直接套脚本咯)

```python
from Crypto.Util.number import *
import re
from Crypto.Cipher import AES

Zx.<x> = ZZ[]
n = 49
q = 128
p = 3
h=14*x^48 + 92*x^47 + x^46 + 95*x^45 + 115*x^44 + 119*x^43 + 10*x^42 + 48*x^41 + 11*x^40 + 117*x^39 + 19*x^38 + 84*x^37 + 36*x^36 + 3*x^35 + 16*x^34 + 87*x^33 + 58*x^32 + 84*x^31 + 63*x^30 + 84*x^29 + 27*x^28 + 77*x^27 + 7*x^26 + 12*x^25 + 80*x^24 + 127*x^23 + 117*x^22 + 55*x^21 + 13*x^20 + 86*x^19 + 64*x^18 + 118*x^17 + 11*x^16 + 86*x^15 + 12*x^14 + 89*x^13 + 109*x^12 + 28*x^11 + 6*x^10 + 72*x^9 + 68*x^8 + 22*x^7 + 126*x^6 + 121*x^5 + 104*x^4 + 111*x^3 + 40*x^2 + 2*x + 126
e=-44*x^48 + 59*x^47 - 47*x^46 + 22*x^45 + 48*x^44 + 30*x^43 - 37*x^42 + 33*x^41 - 15*x^40 - 26*x^39 + 10*x^38 + 54*x^37 + 47*x^36 + 21*x^35 + 49*x^34 + 55*x^33 + 41*x^32 + 46*x^31 - 23*x^30 - 41*x^29 + 63*x^28 - 61*x^27 - 10*x^26 - 52*x^25 - 13*x^24 - 56*x^23 + 33*x^22 + 40*x^21 - 32*x^20 - 7*x^19 - 26*x^18 + 25*x^17 - 36*x^16 + 57*x^15 + 6*x^14 - 32*x^13 + 40*x^12 - 7*x^11 - 15*x^10 - 13*x^9 - 22*x^8 + 34*x^7 - 38*x^6 + 10*x^5 - 11*x^4 + 58*x^3 + 22*x^2 + 21*x

def mul(f,g):
    return (f * g) % (x^n-1)
def decrypt(pri_key,e):
    f,fp = pri_key
    a = bal_mod(mul(f,e),q)
    b = bal_mod(mul(a,fp),p)
    pt=[]
    for i in b.list():
        pt.append(i)
    return pt
def bal_mod(f,q):
    g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
    return Zx(g)
def lattice(h,q):
    n = 49
    # h = bal_mod(683*h,q)
    grid = Matrix(ZZ,2*n,2*n)
    cof = h.list()
    offset = 0
    for i in range(2*n):
        for j in range(2*n):
            if i<n:
                if j < n:
                    if i==j:
                        grid[i,j] = 1
                else:
                    grid[i,j] = cof[(j-n-offset)%n]
            elif j>=n and i==j:
                grid[i,j] = q
        offset += 1
    GL = grid.BKZ()
    return GL,grid

def inv_mod_prime(f,p):
    T = Zx.change_ring(Integers(p)).quotient(x^n-1)
    return Zx(lift(1 / T(f)))

GL,grid = lattice(h,q)
SVP = list(GL[0])
f = Zx(SVP[:n])
g = Zx(SVP[-n:])
a = bal_mod(mul(f,e),q)
fp = inv_mod_prime(f,p)
pv = (f,fp)
coefs=decrypt(pv,e)

R.<x> = PolynomialRing(ZZ)

def terms(poly_str):
    terms = []
    pattern = r'([+-]?\s*x\^?\d*|[-+]?\s*\d+)'
    matches = re.finditer(pattern, poly_str.replace(' ', ''))
    
    for match in matches:
        term = match.group()
        if term == '+x' or term == 'x':
            terms.append(1)
        elif term == '-x':
            terms.append(-1)
        elif 'x^' in term:
            coeff_part = term.split('x^')[0]
            exponent = int(term.split('x^')[1])
            if not coeff_part or coeff_part == '+':
                coeff = 1
            elif coeff_part == '-':
                coeff = -1
            else:
                coeff = int(coeff_part)
            terms.append(coeff * exponent)
        elif 'x' in term:
            coeff_part = term.split('x')[0]
            if not coeff_part or coeff_part == '+':
                terms.append(1)
            elif coeff_part == '-':
                terms.append(-1)
            else:
                terms.append(int(coeff_part))
        else:
            if term == '+1' or term == '1':
                terms.append(0)
                terms.append(-0)
    return terms
def gen_key(poly_terms):
    binary = [0] * 128
    for term in poly_terms:
        exponent = abs(term)
        if term > 0 and exponent <= 127:  
            binary[127 - exponent] = 1
    binary_str = ''.join(map(str, binary))
    hex_key = hex(int(binary_str, 2))[2:].upper().zfill(32)
    return hex_key
terms=terms(str(R(coefs)))
key = bytes.fromhex(gen_key(terms))

aes = AES.new(key = key, nonce=b'20250410', mode=AES.MODE_CTR)
c = b't\xf5\x17?\xc8\xc2\x87\xc4\xa5\xcc\xe3\x03\xc2\xb0\xa4\x1b\x07s\xb3\x9e\x96\x16v@\xbb\xbdc\x85\x9cY\xca'
flag=aes.decrypt(c)
print(flag)

```

> nex{NTRU_l5_Ok_BUT_noO0o0O_NTR}
>

## 3.选择大于努力
代码

```python
def f(x):
    x ^= ((x >> 11) & 0xb451411bb451411b)
    x ^= ((x << 13) & 0x451411cc451411cc)
    x ^= ((x >> 17) & 0xaa191981aa191981)
    x ^= ((x >> 19) & 0xb1919810b1919810)
    x ^= ((x << 23) & 0x451411cd451411cd)
    x ^= ((x >> 29) & 0xb451411ab451411a)
    x ^= ((x << 31) & 0x451411cb451411cb)
    x ^= ((x << 37) & 0xaa19198caa19198c)
    x ^= ((x >> 41) & 0xb191981db191981d)
    x ^= ((x << 43) & 0x451411ce451411ce)

    x ^= ((x >> 10) & 0xb451411bb451411b)
    x ^= ((x << 12) & 0x451411cc451411cc)
    x ^= ((x >> 14) & 0xaa191981aa191981)
    x ^= ((x >> 16) & 0xb1919810b1919810)
    x ^= ((x << 20) & 0x451411cd451411cd)
    x ^= ((x >> 24) & 0xb451411ab451411a)
    x ^= ((x << 26) & 0x451411cb451411cb)
    x ^= ((x << 28) & 0xaa19198caa19198c)
    x ^= ((x >> 30) & 0xb191981db191981d)
    x ^= ((x << 32) & 0x451411ce451411ce)

    return x 

def calc(n):
    x = 0x1122334455667788
    for _ in range(n):
        x = f(x)
    return x

#print('nex{%s}' % hex(calc(11111111111111111111111111111111111111111111111))[2:])
```

学长提示是从mt19937得到灵感的选择明文攻击。

[可以看这篇文章逆向extractnumber的部分](https://www.anquanke.com/post/id/205861#h2-2)

类似地，通过选择明文攻击的方法求出f(x)的对应矩阵 最后再GF(2)里求矩阵的高次幂


