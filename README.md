# hdw-c
A mini  hierarchical deterministic wallets capable of deriving private keys only

## 环境要求
- gcc>=9.3.0
- cmake>=3.16

## 快速开始

```bash
rm -rf build
mkdir build
cd build

# 包含测试
cmake -DENABLE_TESTING=1 ..

make -j
```

## 注意事项
- [zdyszm/coinaddress] 实现的 HMAC512 有 bug。

## 参考文献
- [sammyne/bip32]
- [zdyszm/coinaddress]

[sammyne/bip32]: https://github.com/sammyne/bip32
[zdyszm/coinaddress]: https://github.com/zdyszm/coinaddress
