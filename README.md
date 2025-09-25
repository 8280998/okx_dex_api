# okx_dex_api
## 说明：通过okx的钱包交易需要扣除服务，但使用okx的api交易却无需扣除服务费。本程序可以批量交易指定地址的山寨币交易。因为刷base链空投的原因，当前只支持BASE链交易。其他链待后面更新添加

# 无责声明：本程序为明文代码，运行前请先审核代码安全性。确定使用后，运行时产生任何损失均与本代码无关（GAS消耗，互换无常损失为正常现象）。
## 1 运行环境
下载并安装Python 3.8或更高版本，安装所需Python库

    sudo apt update && sudo apt install python3 python3-pip
    pip3 install requests web3
    
## 2 准备address.txt
准备刷号的地址每个私匙一行

## 3 参数设置 
使用okx的聚合交易功能，申请key才能正常使用，申请连接： https://web3.okx.com/zh-hans/build/dev-portal

直接在gui添加，点击保存配置自动生成config.json，如下图。或者编辑config.json文件后运行

<img width="1830" height="400" alt="image" src="https://github.com/user-attachments/assets/e2c02135-96d9-47b4-a189-d4762d21fcba" />

## 4 运行
    python3 okx.py

运行界面如下：  
<img width="1844" height="1548" alt="image" src="https://github.com/user-attachments/assets/8b209f4c-e185-43e9-9ac5-6a9a0b914b36" />

