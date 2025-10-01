# okx_dex_api
## 说明：通过okx的钱包交易需要扣除服务，但使用okx的api交易却无需扣除服务费。本程序可以批量交易指定地址的山寨币交易。因为刷base链空投的原因，当前只支持BASE链交易。其他链待后面更新添加(待添加OP，BSC，ARB等EVM链)
## Note: Transactions through OKX wallets require service charges, but transactions using OKX APIs do not require service charges. This program can batch trade altcoins at a specified address. Due to the Base Chain airdrop, only BASE Chain transactions are currently supported. Other chains will be added in future updates.

# 无责声明：本程序为明文代码，运行前请先审核代码安全性。确定使用后，运行时产生任何损失均与本代码无关（GAS消耗，互换无常损失为正常现象）。
# Disclaimer: This program is plain text code. Please review the code security before running it. Once you confirm your use, any losses incurred during operation are not related to this code (GAS consumption and exchange impermanence losses are normal).

### 更新说明：okx的api已更新到V6，本程序也更新为V6的api。
### 其中新增一个参数如下说明：(可选，默认值为 90%) 允许的价格影响百分比 (介于 0 和 100 之间)。当用户设置了 priceImpactProtectionPercent 后，如果估算的价格影响超过了指定的百分比，将会返回一个错误。例如，如果 priceImpactProtectionPercent = 25，任何价格影响高于 25% 的报价都将返回错误。这是一个可选开启的功能，默认值为 90。当百分比被设置为 100 时，此功能将被禁用，也就是说，每一笔交易都会被允许通过。

## 1 运行环境
下载并安装Python 3.8或更高版本，安装所需Python库

    sudo apt update && sudo apt install python3 python3-pip
    pip3 install requests web3
    sudo apt install python3-tk
    
## 2 准备address.txt
准备刷号的地址每个私匙一行

One line per private key for each address

## 3 参数设置 
使用okx的聚合交易功能，申请key才能正常使用，申请连接： https://web3.okx.com/zh-hans/build/dev-portal

To use OKX's aggregated trading function, you need to apply for a key. To apply for a connection: https://web3.okx.com/zh-han/build/dev-portal

直接在gui添加，点击保存配置自动生成config.json，如下图。或者编辑config.json文件后运行

Add directly in the GUI, click Save Configuration to automatically generate config.json, as shown below. Or edit the config.json file and run

<img width="1830" height="400" alt="image" src="https://github.com/user-attachments/assets/e2c02135-96d9-47b4-a189-d4762d21fcba" />

## 4 运行

okx_v5

    python3 okx.py

okx_v6

    python3 okx_v6.py
    
运行界面如下：  
<img width="1844" height="1548" alt="image" src="https://github.com/user-attachments/assets/8b209f4c-e185-43e9-9ac5-6a9a0b914b36" />

