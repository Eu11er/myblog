---
title: nex3.28-3.30wp
published: 2025-03-31
description: '那道mt19937真的花了我好久'
image: ''
tags: [rc4, mt19937,RSA,lattice,LCG]
category: 'ctf'
draft: false 
lang: ''
---

# nex3.28-3.30wp

## Crypto
### 1.<font style="color:rgba(0, 0, 0, 0.88);">Modulus_Wanderer2</font>
加密代码

```python
from Crypto.Util.number import *
from secret import flag
import random

assert flag[:5] == b'nex{U'

class prng:     
    def __init__(self, seed = getPrime(256)): 
        self.state = seed
        self.p = getPrime(256)
        self.a = random.randint(1,self.p)
        self.b = random.randint(1,self.p)
    def next(self): 
        self.state = (self.state * self.a + self.b) % self.p
        return self.state

flag = [bin(i)[2:].rjust(8,'0') for i in flag]
flag = ''.join(flag)
C = []
pr = prng()
for i in flag:
    t = pr.next()
    if i == '0':
        C.append(t)
    else:
        C.append(random.randint(0,2**256))

print(f"C = {C}")
```



简单的破解LCG,flag转换成二进制8位填充，二进制中如果是0就输出生成器的值，如果是1就输出randint(0,2**256)的值，也就是说我们要判断C列表的每个数是否是LCG生成的数，当然尝试还原LCG的状态，我们知道flag的前五个字符，我们把它们转换成二进制输出

```python
flag=b'nex{U'
flag=[bin(i)[2:].rjust(8,'0') for i in flag]
flag=''.join(flag)
print(flag)
```

> output:0110111001100101011110000111101101010101
>

我们不知道LCG的任何情况，要解方程，首先尝试恢复p，直接解方程做不出来，我们尝试凑几个mod p=0的量，然后用欧几里得算法求出p

[可以看这篇文章](https://bebettercoder.github.io/2021/12/30/%E7%BA%BF%E6%80%A7%E5%90%8C%E4%BD%99%E7%94%9F%E6%88%90%E5%99%A8%EF%BC%88LCG%EF%BC%89-%E5%8E%9F%E7%90%86%E5%8F%8A%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F%EF%BC%88%E4%B8%80%EF%BC%89/)

但是按照这篇文章，我们需要五个连续（或者至少间隔均匀的）LCG生成的值，这样就可以生成四个间隔量t,就能凑出两个k*p形式的，然后GCD一下得到p

但是我们这里没有五个连续均匀的生成值，我们可以使用两组四个连续均匀的生成值，根据之前二进制输出的内容，我们有C[21]~C[24]为一组是连续生成值，C[32],C[34],C[36],C[38]为一组连续均匀生成值

简单给个证明

$ 显然，当flag对应位二进制为0的时候，C[n]为LCG生成的第n+1个值，设\\
t_0=C[22]-C[21]\\
t_1=C[23]-C[22]\\
t_2=C[24]-C[23]\\
\because C[n+1]=(A\cdot C[n]+B)\bmod p\\
t_1=(A\cdot C[22]+B)-(A\cdot C[21]+B)=A\cdot t_0\\
即t_{n+1}=A\cdot t_n\\
可以推出(t_2t_0-t_1^2)\equiv0 \pmod p\\
同理可以得到另一个模p为0的量，于是得到p,得到p之后变为常规的解方程，还原LCG的状态\\
 $

还原之后简单检测C中的数字是否为LCG的值，还原flag

```python
rom Crypto.Util.number import *

flag=b'nex{U'
flag = [bin(i)[2:].rjust(8,'0') for i in flag]
flag = ''.join(flag)

C=

t0=C[22]-C[21]
t1=C[23]-C[22]
t2=C[24]-C[23]
var1=t2*t0-t1*t1

s0=C[34]-C[32]
s1=C[36]-C[34]
s2=C[38]-C[36]

var2=s2*s0-s1*s1
p=GCD(var1,var2)
A=(t1*inverse(t0,p))%p
B=(C[22]-A*C[21])%p
class prng:     
    def __init__(self, seed = getPrime(256)): 
        self.state = C[0]
        self.p = p
        self.a = A
        self.b = B
    def next(self): 
        self.state = (self.state * self.a + self.b) % self.p
        return self.state

real_number=[C[0]]
b_flag=''
pr=prng()
for i in range(383):
    r=pr.next()
    real_number.append(r)

for i in range(384):
    if C[i]==real_number[i]:
        b_flag+='0'
    else:
        b_flag+='1'
print(''.join([chr(int(b_flag[i:i+8], 2)) for i in range(0, len(b_flag), 8)]))
```

> nex{UA5dds4D_1_7h1nk_7h3_LCg_1s_thE_M0sT_UN54Fe}
>

### 2.<font style="color:rgba(0, 0, 0, 0.88);">RSABag</font>
跟RSA没什么关系，简单的格

用LLL约简后就可以找到原来线性方程的解

```python
from Crypto.Util.number import bytes_to_long

n = 76978172555933856174847296118918726731213057982431111593599110772654100318563117593045995640424012196655251123532999620134440479664168859899566084201703159064218134516469878592753929832056583964888348741581352440769618412818913207538690862417132158124725113913675810869730410914812967173657083134732063690399
e = 65537
sum_total = 146044223495179848034180410994135992148279538573238065848133872768524900880047404982385755875024337794550729905089090204977460445743755331858563815073937292922569024792366552111169511772496543376508467301415289366945401707925705913795757923751286864530292804149533921184253128445178941078921319448366783750564780

s = b'RSA_is_easy_but_if_I_add_others_.....'
K = bytes_to_long(s)
m = [pow(K + i, e, n) for i in range(36)]

M = 2^100
dim = 37 

rows = []
for i in range(36):
    row = [0] * dim
    row[i] = 1        
    row[-1] = m[i] * M 
    rows.append(row)


row = [0] * dim
row[-1] = -sum_total * M
rows.append(row)

mat = matrix(ZZ, rows)
lll = mat.LLL()

found = False
for row in lll:
    if row[-1] == 0:  
        coeffs = row[:36] 
        if all(0 <= c <= 255 for c in coeffs):
            flag = bytes(coeffs).decode()
            print(flag)
            found = True
            break

if not found:
    print("bad")
```

> nex{wElComE_t0_Th3_worID_OF_1ATTice}
>

### 3.rcfour
花了很长时间，但是学到挺多东西

看看rcfour

```python
def rcfour(key, data):
    S = list([i % 255 for i in range(256)])
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    loop=0
    result = bytearray()
    for char in data:
        loop+=1
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i] = S[j]
        S[j] = S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(char ^ k)
    
    return bytes(result)
```

显然这个rc4很幽默(所以才叫rcfour)，第十五行和第十六行犯了编程初学者人之常情的错误，起不到交换的作用，知识将S[i]用S[j]覆盖了，由于data是很长的一段数据，合理猜测cipher加密的末尾一部分的时候此时S-box已经变成完全一样的数了，所以cipher末尾变成了data异或某个数k(k在0~255)

看看RSA

```python
key = random.randbytes(256)
c = rcfour(key, bytes([random.getrandbits(8) for _ in range(50000)]))
with open('cipher.txt','w') as f:
    f.write(bytes.hex(c))

N = nextprime(random.getrandbits(512))
C = pow(flag,65537,N)
print(f"C = {C}")
```

显然只要知道N就可以得到flag，如果要得到N就需要知道random.getrandbits(512)的值，所以我们就需要破解这个伪随机数生成器(MT19937)，根据对梅森旋转的了解，我们只需要624个MT19937生成的32位bit数，就可以在秒内还原生成器的状态，但我们只有getrandbits(8)^k的数值，由于其生成机制，getrandbits(8)的生成方式其实是生成一个32bit数然后取高八位，但我们如果有超过624*32位连续生成的比特值，就可以在花费一定时间的前提下构造矩阵和遍历解空间来找到内部状态

但我们得到的是data异或k的状态，如果直接使用8*2500位连续比特恢复，遍历所有256个k的话，在我的机器上大概要跑256*5/60=21.33h，但正是因为我们data数据太多了，所以我们可以豪横一点，把8bit的低7位全扔掉，就取最高一位，这样就把异或的范围变小了(只有0或1)，所以我们用1*20000个连续bit恢复，大概可以在十几分钟内恢复生成器的state，得到N然后得到flag

key是cipher中取的最后20000个生成数的最高位，手动尝试之后得到异或的是1,k=245

```python
from Crypto.Util.number import *
from random import *
from tqdm import *
from sympy import nextprime
n=20000
C=1836184682169748070989133840042351952294695964110407163899271185441343825945147993536644513381704679641476812132479929805459665176655835013432635869984651
e=0x10001
key=
rng=Random()
def getRows(rng):
    row=[]
    for i in range(n):
        row+=list(map(int, (bin(rng.getrandbits(1))[2:].zfill(1))))
    return row
def reMT(key):    
    M=[]
    for i in tqdm_notebook(range(19968)):
        
        state = [0]*624
        temp = "0"*i + "1"*1 + "0"*(19968-1-i)
        for j in range(624):
            state[j] = int(temp[32*j:32*j+32],2)
        rng.setstate((3,tuple(state+[624]),None))
        M.append(getRows(rng))
    M=Matrix(GF(2),M)
    y=[]
    for i in range(n):
        y+=list(map(int, (bin(key[i])[2:].zfill(1))))
    y=vector(GF(2),y)
    s=M.solve_left(y)
    #print(s)
    G=[]
    for i in range(624):
        C=0
        for j in range(32):
            C<<=1
            C|=int(s[32*i+j])
        G.append(C)
    for i in range(624):
        G[i]=int(G[i])
    return G
    
key_xor=[]
for i in range(len(key)):
    key_xor.append(key[i]^^1)
import random
G=reMT(key_xor)
RNG1 = random.Random()
RNG1.setstate((int(3),tuple(G+[int(624)]),None))
temp=[RNG1.getrandbits(8) for _ in range(20000)]
N=nextprime(RNG1.getrandbits(512))
phi=N-1
d=inverse(e,phi)
m=pow(C,d,N)
flag=long_to_bytes(m)
print(flag)
```

> nex{rC4_sBoX_MUsT_b3_SHUfFLed}
>



