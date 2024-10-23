import sys
import pyshark
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint
import json
import binascii
import argparse
import time
import re
from jawa.cf import ClassFile
from io import BytesIO
from jawa.constants import String
from RestrictedPython import safe_globals, compile_restricted
import os
import builtins
from flask import Flask, send_from_directory, Response, request, stream_with_context
import webbrowser
import threading
import random
import jsonlines
import fcntl

console = Console()

# 定义匹配模式
php_patterns = {
    # 匹配供暖
    'operations' : {
        'init': r'main\(\$content\);',
        'info': r'main\(\$whatever\);',
        'command': r'main\(\$cmd,\$path\);',
        'shell': r'main\(\$type,\$bashPath,\$cmd,\$whatever\);',
        'file': r'main\(\$mode,\$path,\$hash,\$blockIndex,\$blockSize,\$content,\$charset,\$newpath,\$createTimeStamp,\$accessTimeStamp,\$modifyTimeStamp\);',
        'portmap': r'main\(\$action,\$targetIP,\$targetPort,\$socketHash,\$remoteIP,\$remotePort,\$extraData\);',
        'socksproxy': r'main\(\$action,\$listenPort,\$socketHash,\$extraData\);',
        'reverseshell': r'main\(\$type,\$ip,\$port\);',
        'database': r'main\(\$type,\$host,\$port,\$user,\$pass,\$database,\$sql\);',
    },
    
    # 匹配参数
    'args': {
        'mode': r'\$mode="([^"]+)"',
        'path': r'\$path="([^"]+)"',
        'hash': r'\$hash="([^"]+)"',
        'blockIndex': r'\$blockIndex="([^"]+)"',
        'blockSize': r'\$blockSize="([^"]+)"',
        'content': r'\$content="([^"]+)"',
        'charset': r'\$charset="([^"]+)"',
        'newpath': r'\$newpath="([^"]+)"',
        'createTimeStamp': r'\$createTimeStamp="([^"]+)"',
        'accessTimeStamp': r'\$accessTimeStamp="([^"]+)"',
        'modifyTimeStamp': r'\$modifyTimeStamp="([^"]+)"',
        'cmd': r'\$cmd="([^"]+)"',
        'type': r'\$type="([^"]+)"',
        'bashPath': r'\$bashPath="([^"]+)"',
        'whatever': r'\$whatever="([^"]+)"',
        'action': r'\$action="([^"]+)"',
        'targetIP': r'\$targetIP="([^"]+)"',
        'targetPort': r'\$targetPort="([^"]+)"',
        'listenPort': r'\$listenPort="([^"]+)"',
        'socketHash': r'\$socketHash="([^"]+)"',
        'remoteIP': r'\$remoteIP="([^"]+)"',
        'remotePort': r'\$remotePort="([^"]+)"',
        'extraData': r'\$extraData="([^"]+)"',
        'ip': r'\$ip="([^"]+)"',
        'port': r'\$port="([^"]+)"',
        'port': r'\$port="([^"]+)"',
        'host': r'\$host="([^"]+)"',
        'user': r'\$user="([^"]+)"',
        'pass': r'\$pass="([^"]+)"',
        'database': r'\$database="([^"]+)"',
        'sql': r'\$sql="([^"]+)"'
    }
}

# 定义匹配模式
asp_patterns = {
    'init': r'Sub main\(arrArgs\).*?content=arrArgs\(0\).*?echo\(content\).*?End Sub',
    'info': r'Sub main\(arrArgs\).*?on error resume next.*?dim i,ws,Sa,sysenv,envlist,envlists,cpunum,cpuinfo,os',
    'file': r'Sub main\(arrArgs\).*?mode=arrArgs\(0\).*?path=arrArgs\(1\).*?Dim finalResult',
    'command': r'Sub main\(arrArgs\).*?cmd=arrArgs\(0\).*?runCmd\(cmd\).*?End Sub',
    'database': r'Sub main\(arrArgs\).*?on error resume next.*?dbType=arrArgs\(0\).*?host=arrArgs\(1\).*?port=arrArgs\(2\).*?username=arrArgs\(3\).*?pass=arrArgs\(4\).*?database=arrArgs\(5\).*?sql=arrArgs\(6\)'
}

def get_php_operation(category):
    operations = {
        "init": "初始化",
        "info": "信息获取",
        "shell": "虚拟终端",
        "command": "命令执行",
        "file": "文件操作",
        "database": "数据库操作",
        "portmap": "端口转发",
        "socksproxy": "远程Socks代理",
        "reverseshell": "反弹shell",
        "custom_code": "自定义代码执行"
    }
    for key, value in operations.items():
        if key in category:
            return value
    return f"未知操作: {category}"


def get_asp_operation(category):
    operations = {
        "init": "初始化",
        "info": "信息获取",
        "shell": "虚拟终端",
        "command": "命令执行",
        "file": "文件操作",
        "database": "数据库操作",
        "portmap": "端口转发",
        "ReversePortMap": "反向DMZ",
        "RemoteSocksProxy": "远程Socks代理",
        "ConnectBack": "反弹shell",
        "Loader": "DLl加载器",
        "custom_code": "自定义代码执行"
    }
    for key, value in operations.items():
        if key in category:
            return value
    return f"未知操作: {category}"


def get_aspx_operation(source_file_name):
    operations = {
        "Echo.dll": "初始化",
        "BasicInfo.dll": "信息获取",
        "RealCMD.dll": "虚拟终端",
        "Cmd.dll": "命令执行",
        "FileOperation.dll": "文件操作",
        "Database.dll": "数据库操作",
        "PortMap.dll": "端口转发",
        "ReversePortMap.dll": "反向DMZ",
        "RemoteSocksProxy.dll": "远程Socks代理",
        "ConnectBack.dll": "反弹shell",
        "Loader.dll": "DLl加载器",
        "Eval.dll": "自定义代码执行"
    }
    for key, value in operations.items():
        if key in source_file_name:
            return value
    return f"未知操作: {source_file_name}"

def get_jsp_operation(source_file_name):
    operations = {
        "Eval.java": "初始化",
        "BasicInfo.java": "信息获取",
        "RealCMD.java": "虚拟终端",
        "Cmd.java": "令执行",
        "FileOperation.java": "文件操作",
        "Database.java": "数据库操作",
        "PortMap.java": "端口转发",
        "ReversePortMap.java": "反向DMZ",
        "RemoteSocksProxy.java": "远程Socks代理",
        "ConnectBack.java": "反弹shell",
        "Loader.java": "jar加载器",
        "Eval.java": "自定义代码执行"
    }
    for key, value in operations.items():
        if key in source_file_name:
            return value
    return f"未知操作: {source_file_name}"


def php_xor_decrypt(data, key):
    # 尝试进行base64解码
    try:
        base64_decoded = base64.b64decode(data, validate=True)
        # console.print(f"[green]Base64解码成功[/green]")
    except:
        console.print("[yellow]Base64解码失败, 直接返回[/yellow]")
        return data
    key_bytes = key.encode('utf-8')
    decrypted = bytearray()
    for i, byte in enumerate(base64_decoded):
        decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
    return bytes(decrypted)

def php_aes_decrypt(data, key):
    # 尝试进行base64解码
    try:
        base64_decoded = base64.b64decode(data, validate=True)
        # console.print(f"[green]Base64解码成功[/green]")
    except:
        # console.print("[yellow]Base64解码失, 直接返回[/yellow]")
        return data
    key_bytes = key.encode('utf-8')[:16].ljust(16, b'\0')
    iv = b'\x00' * 16
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(base64_decoded), AES.block_size)
    except ValueError:
        # 如果解密后的数据没有正确的填充，尝试不进行去填充
        decrypted = cipher.decrypt(base64_decoded)
    return decrypted

def asp_xor_decrypt(data, key):
    key_bytes = key.encode('utf-8')
    decrypted = bytearray()
    for i, byte in enumerate(data):
        key_index = ((i & 15) + 1) % len(key_bytes)  # 使用与原ASP代码相同的索引逻辑
        decrypted.append(byte ^ key_bytes[key_index])
    return decrypted.decode('utf-8', errors='ignore')  # 将字节数组解码为UTF-8字符串


def aspx_aes_decrypt(data, key):
    try:
        # 按照 ASP 的行为，将 key 使用系统默认编码进行转换
        key = key.encode('UTF-8')  
        
        # 确保密钥长度为 16 字节（128 位），ASP 中是这样处理的
        key = key[:16].ljust(16, b'\0')
        
        # 创建 AES 解密器，使用 CBC 模式，并使用相同的 key 作为 IV
        cipher = AES.new(key, AES.MODE_CBC, iv=key)
        
        # 解密数据
        decrypted_data = cipher.decrypt(data)
        
        # 移除 PKCS7 填充
        padding_length = decrypted_data[-1]
        if 1 <= padding_length <= 16:
            return decrypted_data[:-padding_length]
        else:
            return decrypted_data  # 如果填充长度异常，返回未去除填充的结果
    except Exception as e:
        # 捕获错误信息，方便调试
        return data

def jsp_aes_decrypt(data, key):
    # 尝试进行base64解码
    try:
        base64_decoded = base64.b64decode(data, validate=True)
        # console.print(f"[green]Base64解码成功[/green]")
    except:
        console.print("[yellow]Base64解码失败，直接返回[/yellow]")
        return data
    
    try:
        key_bytes = key.encode('utf-8')[:16].ljust(16, b'\0')  # 确保密钥长度为16字节
        cipher = AES.new(key_bytes, AES.MODE_ECB)

        # 直接解密数据，因为已经进行过 base64 解码
        decrypted_data = cipher.decrypt(base64_decoded)
        # 移 PKCS7 填充
        padding_length = decrypted_data[-1]
        if 1 <= padding_length <= 16:
            return decrypted_data[:-padding_length]
        else:
            return decrypted_data  # 如果填充长度异常，返回未去除填充的结果
    except Exception as e:
        # console.print(f"[red]JSP解密错误: {e}[/red]")
        return data


def truncate_long_values(data, max_length=50, max_items=5):
    if isinstance(data, dict):
        truncated = {}
        for i, (k, v) in enumerate(data.items()):
            if i >= max_items:
                truncated['...'] = f'还有 {len(data) - max_items} 项'
                break
            truncated[k] = truncate_long_values(v, max_length, max_items)
        return truncated
    elif isinstance(data, list):
        if len(data) > max_items:
            truncated = [truncate_long_values(item, max_length, max_items) for item in data[:max_items]]
            truncated.append(f'还有 {len(data) - max_items} 项')
            return truncated
        return [truncate_long_values(item, max_length, max_items) for item in data]
    elif isinstance(data, str):
        return data[:max_length] + '...' if len(data) > max_length else data
    else:
        return data


def decode_json_value(value):
    if isinstance(value, str):
        try:
            # 尝试进行base64解码
            decoded = base64.b64decode(value, validate=True)
            # 检查解码后的内容是否为有效的UTF-8
            decoded_str = decoded.decode('utf-8')
            return decoded_str
        except (UnicodeDecodeError, base64.binascii.Error):
            # 如果base64解码失败或不是有的UTF-8，保留原值
            return value
    elif isinstance(value, dict):
        return {decode_json_value(k): decode_json_value(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [decode_json_value(item) for item in value]
    else:
        return value

def safe_execute(code, data, key):
    # 创建安全的执行环境
    safe_globals = {
        '__builtins__': dict(builtins.__dict__),
        'data': data,
        'key': key
    }
    
    # 编译并执行代码
    try:
        exec(code, safe_globals)
        if 'custom_decrypt' in safe_globals:
            return safe_globals['custom_decrypt'](data, key)
        else:
            raise Exception("未找到'custom_decrypt'函数")
    except Exception as e:
        # console.print(f"[red]执行自定义解密代码时出错: {e}[/red]")
        return data


def decrypt_data(data, script_type, key, custom_decrypt_code = ''):
    # 将LayerFieldsContainer转换为符串
    if isinstance(data, pyshark.packet.fields.LayerFieldsContainer):
        data = str(data)
    
    # 移除可能存在的冒号
    data = data.replace(':', '')
    
    try:
        # 尝试将十六进制字符串转换为字节
        decoded_data = binascii.unhexlify(data)
        # console.print(f"[green]十六进制解码成功[/green]")
    except binascii.Error:
        console.print("[red]无法解码十六进制数据[/red]")
        return None

    if custom_decrypt_code:
        try:
            decrypted = safe_execute(custom_decrypt_code, decoded_data, key)
            # 在返回之前，确保结果是 bytes 对象
            if isinstance(decrypted, str):
                decrypted = decrypted.encode('utf-8', errors='ignore')
            return decrypted
        except Exception as e:
            console.print(f"[red]自定义解密代码执行失败: {e}[/red]")
            pass
            # 如果自定义解密失败,继续尝试其他解密方法

    # 根据脚本类型选择解密方法
    decrypted = None
    try:
        if script_type == 'php':
            try:
                decrypted = php_aes_decrypt(decoded_data, key)
                # console.print("[green]php aes解密成功[/green]")
            except:
                decrypted = php_xor_decrypt(decoded_data, key)
                # console.print("[green]php xor解密成功[/green]")
        elif script_type == 'asp':
            decrypted = asp_xor_decrypt(decoded_data, key)
            # console.print("[green]asp xor解密成功[/green]")
        elif script_type == 'aspx':
            decrypted = aspx_aes_decrypt(decoded_data, key)
            # console.print("[green]aspx aes解密成功[/green]")
        elif script_type == 'jsp':
            decrypted = jsp_aes_decrypt(decoded_data, key)
            # console.print("[green]jsp aes解密成功[/green]")
        else:
            console.print(f"[red]不支持的脚本类型: {script_type}[/red]")
            return None

        if decrypted is None:
            console.print("[red]解密失败: 未能成功解密数据[/red]")
            return None

        # 在返回之前，确保结果是 bytes 对象
        if isinstance(decrypted, str):
            decrypted = decrypted.encode('utf-8', errors='ignore')
        return decrypted

    except Exception as e:
        console.print(f"[red]解密过程中发生错误: {e}[/red]")
        return None

def format_request_data(request_data, script_type, key):
    result = {}
    if script_type == 'php':
        request_data = request_data.decode('utf-8', errors='ignore')
        # 首先匹配 base64_decode('...') 模式
        base64_pattern = r"base64_decode\('([^']+)'\)"
        match = re.search(base64_pattern, request_data)
        
        result = {'operation': ''}

        if match:
            base64_content = match.group(1)
            try:
                decoded_content = base64.b64decode(base64_content, validate=True).decode('utf-8', errors='ignore')
            except:
                decoded_content = f"无法解码: {base64_content[:30]}..."
            matched = False
            for key, pattern in php_patterns['operations'].items():
                match = re.search(pattern, decoded_content)
                if match:
                    matched = True
                    result['operation'] = get_php_operation(key)

            if not matched :
                result['operation'] = get_php_operation('custom_code')
                result['custom_code'] = decoded_content

            for key, pattern in php_patterns['args'].items():
                match = re.search(pattern, decoded_content)
                if match:
                    # 如果有匹配组，使用第一个匹配组，否则使用整个匹配
                    value = match.group(1) if match.groups() else match.group(0)
                    # 尝试 base64 解码
                    try:
                        result[key] = decode_json_value(value)
                    except:
                        result[key] = value 
        else:
            console.print(request_data)
            exit()
            result['operation'] = get_php_operation('custom_code')
            result['custom_code'] = request_data

    elif script_type == 'asp':
        request_data = request_data.decode('utf-8', errors='ignore')

        result = {'operation': ''}
        matched = False
        for category, pattern in asp_patterns.items():
            match = re.search(pattern, request_data, re.S)
                            
            if match:
                matched = True
                main_match = re.search(r'main Array\((.*)\)', request_data)
                if main_match:
                    main_data = main_match.group(1)
                    args = main_data.split(',')
                    decoded_args = []
                    for arg in args:
                        chrs = re.findall(r'chrw\((\d+)\)', arg)
                        decoded_arg = ''.join(chr(int(num)) for num in chrs)
                        decoded_args.append(decoded_arg)
                    
                    result['operation'] = get_asp_operation(category)
                    result[category] = decoded_args
        
        # 如果没有任何匹配，将原始请求数据保存到 custom_code
        if not matched:
            result['operation'] = get_asp_operation('custom_code')
            result['custom_code'] = request_data
        
        # 将非空字段添加到result中
        result = {field: value for field, value in result.items() if value}

    elif script_type == 'aspx':

        source_file_name = ''
        module_pattern = b'\x3C\x4D\x6F\x64\x75\x6C\x65\x3E\x00'
        module_index = request_data.find(module_pattern)
        if module_index != -1:
            end_index = request_data.find(b'\x00', module_index + len(module_pattern))
            if end_index != -1:
                source_file_name = request_data[module_index + len(module_pattern):end_index].decode('utf-8', errors='ignore')

        result = {'operation': get_aspx_operation(source_file_name)}

        # 查找最后一个 7E7E7E7E 7E7E
        end_pattern = b'\x7E\x7E\x7E\x7E\x7E\x7E'
        end_index = request_data.rfind(end_pattern)
        if end_index != -1:
            end_content = request_data[end_index + len(end_pattern):].decode('utf-8', errors='ignore')
            
            # 解析结尾内容
            content_parts = end_content.split(',')
            for part in content_parts:
                key, value = part.split(':')
                try:
                    # 尝试进行base64解码
                    result[key] = base64.b64decode(value, validate=True).decode('utf-8', errors='ignore')
                except:
                    # 如果base64解码失败,保留原值
                    result[key] = value

    elif script_type == 'jsp':
        try:
            # 将字节数据包装成类文件对象
            class_file = BytesIO(request_data)
            
            # 使用包装后的类文件对象
            cf = ClassFile(class_file)
            
            source_file = cf.attributes.find_one(name='SourceFile')
            if source_file:
                source_file_name = source_file.source_file.value
            else:
                source_file_name = "Unknown"
            
            result = {'operation': get_jsp_operation(source_file_name)}
            
            # 添加从java.py迁移的代码
            init_method = cf.methods.find_one(name='<init>')
            if init_method and init_method.code:
                fields = {
                    'cmd': '', 'path': '', 'content': '', 'whatever': '', 'type': '',
                    'bashPath': '', 'mode': '', 'action': '', 'targetIP': '', 'targetPort': '',
                    'remoteIP': '', 'remotePort': '', 'listenPort': '', 'ip': '', 'port': '',
                    'libPath': '', 'host': '', 'user': '', 'pass': '', 'database': '', 'sql': ''
                }
                last_ldc_value = None
                
                for instruction in init_method.code.disassemble():
                    if instruction.mnemonic == 'ldc':
                        constant_index = instruction.operands[0].value
                        constant = cf.constants.get(constant_index)
                        if isinstance(constant, String):
                            last_ldc_value = cf.constants.get(constant.string.index).value
                
                    elif instruction.mnemonic == 'putstatic':
                        constant_index = instruction.operands[0].value
                        constant = cf.constants.get(constant_index)
                        field_ref = constant.name_and_type
                        if field_ref.name.value in fields and last_ldc_value is not None:
                            try:
                                # 使用严格模式进行base64解码
                                decoded_value = base64.b64decode(last_ldc_value, validate=True).decode('utf-8')
                                fields[field_ref.name.value] = decoded_value
                            except:
                                # 如果解码失败，保留原始值
                                fields[field_ref.name.value] = last_ldc_value
                        last_ldc_value = None
                
                # 将非空字段添加到result中
                result = {field: value for field, value in fields.items() if value}
            
        except Exception as e:
            # console.print(f"[red]解析JSP请求时出错: {e}[/red]")
            pass
    
    return result


def format_response_data(response_data, script_type, key):
    try:
        response_data = response_data.decode('utf-8', errors='ignore')
        # 先尝试解析整个response_data为JSON
        json_data = json.loads(response_data)
        
        # 对整个json_data进行decode_json_value处理
        json_data = decode_json_value(json_data)

        # 如果存在msg字段，对其进行特殊处理
        if 'msg' in json_data.keys():
            msg = json_data['msg']
            try:
                # 尝试将msg解析JSON
                if msg[-2:] == ',]':
                    msg = msg[:-2] + ']'
                msg_json = json.loads(msg)
                json_data['msg'] = decode_json_value(msg_json)
            except Exception as e:
                pass
        return json_data
    except Exception as e:
        # console.print(f"[red]格式化响应数据时出错, 响应数据不是JSON格式: {e}[/red]")
        return response_data

class StreamingJSONLWriter:
    def __init__(self, file_path):
        self.file_path = file_path
        self.writer = jsonlines.open(file_path, mode='w')

    def write_item(self, item):
        self.writer.write(item)

    def close(self):
        self.writer.close()

    @staticmethod
    def _default(obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='ignore')
        return str(obj)

app = Flask(__name__, static_folder='statics')

# 全局变量存储 json_file_path
json_file_path = None

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/statics/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

@app.route('/result.jsonl')
def stream_json():
    start_line = int(request.args.get('start', 0))
    
    @stream_with_context
    def generate():
        with open(json_file_path, 'r') as file:
            
            # 跳过之前的行
            for _ in range(start_line):
                file.readline()
            
            # 读取并发送新的行
            new_lines = file.readlines()
            if not new_lines:
                yield "event: no_data\ndata: \n\n"
            else:
                for line in new_lines:
                    try:
                        data = json.dumps(json.loads(line.strip()))
                        yield f"data: {data}\n\n"
                    except json.JSONDecodeError as e:
                        console.print(f"Error parsing JSON: {e}")
                        console.print(f"Problematic line: {line}")
                        continue
            
            yield "event: close\ndata: \n\n"

    return Response(generate(), content_type='text/event-stream')

def start_http_server(port, file_path):
    global json_file_path
    json_file_path = file_path
    
    console.print(f"服务器启动在 http://localhost:{port}")
    webbrowser.open(f"http://localhost:{port}")
    
    app.run(port=port, debug=False, threaded=True)

def main(pcap_file, url_path, script_type, key, custom_decrypt_code='', preview=False):
    console.print(Panel(f"开始分析 [bold green]{pcap_file}[/bold green]", expand=False))
    console.print(f"URL路径: [cyan]{url_path}[/cyan]")
    console.print(f"脚本类型: [cyan]{script_type}[/cyan]")
    
    json_file_path = f"{pcap_file}_decrypted.jsonl"
    
    if preview:
        port = random.randint(8000, 9000)
        console.print(f"[bold green]正在启动预览服务器...[/bold green]")
        threading.Thread(target=start_http_server, args=(port, json_file_path), daemon=True).start()
    
    capture = pyshark.FileCapture(
        pcap_file, 
        display_filter=f'http.request.uri contains "{url_path}"',
        use_json=True,
        include_raw=True
    )
    
    packet_count = 0
    
    json_writer = StreamingJSONLWriter(json_file_path)
    sessions = {}

    with console.status("[bold green]正在分析数据包...", spinner='moon') as status:
        for packet in capture:  
            packet_count += 1
            
            try:
                http_layer = packet.http
                tcp_layer = packet.tcp
                tcp_stream = packet.tcp.stream

                req_num = int(tcp_layer.nxtseq)
                resp_num = int(tcp_layer.ack)

                full_http_data = packet.http_raw.value + http_layer.file_data_raw[0]

                console.print(Panel(f'[red]TCP流: {tcp_stream}[/red], Req_Num: {req_num}, Resp_Num {resp_num}', expand=False))

                # 处理HTTP请求
                if not hasattr(http_layer, 'response'):
                    console.print(f"[yellow]发现请求[/yellow]: TCP流: {tcp_stream}, Req_Num: {req_num}")

                    if req_num not in sessions.keys():
                        sessions[req_num] = {}

                    if hasattr(http_layer, 'full_uri'):
                        sessions[req_num]['url'] = http_layer.full_uri
                    
                    # 从 full_http_data 中获取请求方法
                    http_data_first_line = binascii.unhexlify(full_http_data[:20])
                    method = http_data_first_line.split(b' ', 1)[0].decode('utf-8', errors='ignore')

                    sessions[req_num]['method'] = method

                    request_data = None
                    if hasattr(http_layer, 'file_data_raw'):
                        request_data = http_layer.file_data_raw[0]
                    
                    if request_data:
                        decrypted_request = decrypt_data(request_data, script_type, key, custom_decrypt_code)
                        if decrypted_request:
                            formatted_request = format_request_data(decrypted_request, script_type, key)
                            sessions[req_num]['request'] = {
                                'raw_data_hex': full_http_data,
                                'decrypted_data_hex': decrypted_request.hex(),
                                'format': formatted_request
                            }
                            console.print("[green]格式化后的请求:[/green]")
                            console.print(truncate_long_values(formatted_request, max_length=50, max_items=10))
                        else:
                            console.print(f"[red]无法解密请求数据[/red]: TCP流: {tcp_stream}, Req_Num: {req_num}")
                    else:
                        console.print(f"[red]无法获取请求数据, 请求中没POST数据.[/red]: TCP流: {tcp_stream}, Req_Num: {req_num}")

                # 处理HTTP响应
                elif hasattr(http_layer, 'response'):
                    console.print(f"[blue]发现响应[/blue]: TCP流: {tcp_stream}, Resp_Num {resp_num}")

                    if resp_num not in sessions.keys():
                        sessions[resp_num] = {}

                    # 从 full_http_data 中获取请求方法
                    http_data_first_line = binascii.unhexlify(full_http_data[:50])
                    if len(http_data_first_line.split(b' ', 1)) > 1:
                        method = http_data_first_line.split(b' ')[1].decode('utf-8', errors='ignore')
                    else:
                        method = "未知方法"
                    sessions[resp_num]['code'] = method

                    response_data = None
                    if hasattr(http_layer, 'file_data_raw'):
                        response_data = http_layer.file_data_raw[0]
                    
                    if response_data:
                        decrypted_response = decrypt_data(response_data, script_type, key, custom_decrypt_code)
                        if decrypted_response:
                            formatted_response = format_response_data(decrypted_response, script_type, key)
                            sessions[resp_num]['response'] = {
                                'raw_data_hex': full_http_data,
                                'decrypted_data_hex': response_data if formatted_response == decrypted_response else decrypted_response.hex(),
                                'format': formatted_response
                            }
                            console.print("[green]格式化后的响应:[/green]")
                            console.print(truncate_long_values(formatted_response))
                        else:
                            console.print(f"[red]无法解密响应数据[/red]: Resp_Num {resp_num}")
                    else:
                        console.print(f"[red]无法获取响应数据, 响应中没有数据.[/red]: Resp_Num {resp_num}")

                    # 检查是否存在对应的请求
                    if 'request' in sessions[resp_num]:
                        # 写入完整的会话数据
                        json_writer.write_item(sessions[resp_num])
                        del sessions[resp_num]  # 从sessions字典中删除已写入的会话
                    else:
                        console.print(f"[yellow]警告: 响应 {resp_num} 没有对应的请求，暂不写入[/yellow]")

            except Exception as e:
                console.print(f"[bold red]处理数据包时出错[/bold red]: {e}")
                continue
            
            console.print(f"-" * 50)

            # 每处理 5 个数据包更新一次状态
            if packet_count % 5 == 0:
                status.update(f"[bold green]已分析 {packet_count} 个数据包...")
                time.sleep(0.1)

    console.print(f"\n总共分析了 [bold]{packet_count}[/bold] 个数据包")

    # 处理未匹配的请求和响应
    for session_key, session in sessions.items():
        console.print(f"[yellow]警告: 找到未匹配的会话[/yellow]: {session_key}")
        json_writer.write_item(session)

    # 关闭文件
    json_writer.close()

    console.print(f"[bold green]解密结果已保存到文件: {json_file_path}[/bold green]")

    if preview:
        input("按Enter键退出预览服务...")

def file_path(path):
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"错误: 文件 '{path}' 不存在")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='解密Behinder流量')
    parser.add_argument('-f', '--file', required=True, type=file_path, help='pcap文件路径')
    parser.add_argument('-u', '--url', required=True, help='URL路径, 例如: /uploads/shell.php')
    parser.add_argument('-t', '--type', required=True, choices=['php', 'asp', 'aspx', 'jsp'], help='脚本类型')
    parser.add_argument('-k', '--key', required=True, help='密钥')
    parser.add_argument('-c', '--custom_code', type=file_path, help='自定义解密代码文件路径。请参考 custom_decrypt_example.py 文件了解如何编写自定义解密函数。')
    parser.add_argument('-p', '--preview', action='store_true', help='启动预览服务器')

    # 添自定义帮助信息
    parser.epilog = """
自定义解密代码 (-c/--custom_code):
您可以提供一个包含自定义解密函数的Python文件。该文件应包含一个名为'custom_decrypt'的函数,具有以下特征:

1. 函数名必须是'custom_decrypt'
2. 函数应接受两个参数: data (bytes类型,request和response原始数据) 和 key (字符串类型)
3. 函数应返回解密后的数据 (bytes类型)
4. 函数中可以使用Python的基本功能和import功能,出于安全考,请务必检测解密函数中不含有后门程序.

请参考 custom_decrypt_example.py 文件了解如何编写自定义解密函数。
    """

    parser.formatter_class = argparse.RawDescriptionHelpFormatter  # 这行确保 epilog 中的换行符被保留

    args = parser.parse_args()

    custom_decrypt_code = ''
    if args.custom_code:
        with open(args.custom_code, 'r') as f:
            custom_decrypt_code = f.read()

    if args.preview:
        port = random.randint(8000, 9000)
        json_file_path = f"{args.file}_decrypted.jsonl"
        threading.Thread(target=start_http_server, args=(port, json_file_path), daemon=True).start()

    main(args.file, args.url, args.type, args.key, custom_decrypt_code, args.preview)
