# Behinder流量解密工具

这是一个用于解密Behinder（冰蝎）webshell流量的Python工具。它能够分析pcap文件，解密并格式化Behinder的HTTP请求和响应数据。

## 功能特点

1. 支持解析pcap文件中的HTTP流量
2. 支持多种webshell类型：PHP、ASP、ASPX、JSP
3. 能够解密Behinder的加密流量
4. 针对asmx、自定义传输协议等，支持通过编写自定义解密函数实现解密，解密函数会接受到原始的请求数据
5. 格式化并输出解密后的请求和响应数据
6. 将解密结果保存为JSON文件，保存了原始的和解密后的16进制数据、解析后的数据

## 安装

1. 克隆此仓库：
   ```
   git clone https://github.com/ba0gu0/behinder-decryptor.git
   ```

2. 安装依赖：
   ```
   pip install -r requirements.txt
   ```

## 使用方法

基本用法：

```
python Behinder-Decrypt.py -f <pcap文件> -u <URL路径> -t <脚本类型> -k <密钥> [-c <自定义解密代码文件>]
```

参数说明：
- `-f, --file`: pcap文件路径（必需）
- `-u, --url`: URL路径，例如 `/uploads/shell.php`（必需）
- `-t, --type`: 脚本类型，可选值：php, asp, aspx, jsp（必需）
- `-k, --key`: 密钥（必需）
- `-c, --custom_code`: 自定义解密代码文件路径（可选）

示例：
```
python Behinder-Decrypt.py -f capture.pcap -u /uploads/shell.php -t php -k behinder_secret_key
```

## 自定义解密

如果默认的解密方法无法正确解密流量，您可以提供自定义的解密函数。创建一个Python文件，其中包含名为`custom_decrypt`的函数，并使用`-c`参数指定该文件。

自定义解密函数应具有以下特征：
1. 函数名必须是`custom_decrypt`
2. 接受两个参数：`data`（bytes类型，原始数据）和`key`（字符串类型，密钥）
3. 返回解密后的数据（bytes类型）

请参考`custom_decrypt_example.py`文件了解如何编写自定义解密函数。

## 输出

工具将在控制台输出解密和格式化后的数据，并将完整结果保存为JSON文件（文件名格式：`<pcap文件名>_decrypted.json`）。

## 注意事项

- 请确保您有权限分析目标流量。
- 本工具仅用于安全研究和授权测试目的。
- 使用自定义解密代码时，请确保代码安全可靠。

## 贡献

欢迎提交问题报告、功能请求和代码贡献。请遵循标准的GitHub流程：fork仓库，创建功能分支，提交更改，并创建拉取请求。

## 许可证

本项目采用MIT许可证。详情请参阅LICENSE文件。