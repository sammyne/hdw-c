# hdw-c
A mini  hierarchical deterministic wallets capable of deriving private keys only

## 环境要求
- gcc>=9.3.0
- cmake>=3.16

## 快速开始

### 基于 CMake
```bash
rm -rf build
mkdir build
cd build

#    WITH_TEST=1 指示包含测试
# WITH_EXAMPLE=1 指示包含示例程序
cmake -DWITH_EXAMPLE=1 -DWITH_TEST=1 ..

make -j
```

最后会在 build/src 目录产出 libhdw.a 静态库文件。

### 基于 GNU Make

```bash
make -j

# 运行示例程序
make ckd
```

最后会在 _build 目录产出 libhdw.a 静态库文件以及说明 API 的头文件夹 include。

## 项目介绍

核心 API 参见 [api.h](./include/hdw/api.h)。

## 示例

示例 | 源文件 | 描述
----|-------|------
ckd | [main.cxx](./examples/ckd/main.cxx) | 私钥派生

## 注意事项
- [zdyszm/coinaddress] 实现的 HMAC512 有 bug。

## 参考文献
- [sammyne/bip32]
- [zdyszm/coinaddress]

[sammyne/bip32]: https://github.com/sammyne/bip32
[zdyszm/coinaddress]: https://github.com/zdyszm/coinaddress
