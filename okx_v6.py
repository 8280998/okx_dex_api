import random
import time
import json
import requests
import datetime
import hmac
import hashlib
import base64
import urllib.parse
from web3 import Web3
from web3.exceptions import TransactionNotFound
import logging
import os
import signal
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('trade.log'),
        logging.StreamHandler()
    ]
)

# 默认链配置，需要更多链支持得去config.json添加
DEFAULT_NETWORKS = {
    "base": {
        "chain_id": 8453,
        "rpc_url": "https://mainnet.base.org",
        "default_token_address": "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA",  # USDbC on Base
        "default_target_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # USDC on Base
    },
    "op": {
        "chain_id": 10,
        "rpc_url": "https://mainnet.optimism.io",
        "default_token_address": "0x7F5c764cBc14f9669B88837ca1490cCa17c31607",  # USDC.e on OP
        "default_target_address": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"  # USDC on OP
    }
}

# ERC20 ABI
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [
            {"name": "_owner", "type": "address"},
            {"name": "_spender", "type": "address"}
        ],
        "name": "allowance",
        "outputs": [{"name": "remaining", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_spender", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [{"name": "success", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "success", "type": "bool"}],
        "type": 'function'
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_from", "type": "address"},
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transferFrom",
        "outputs": [{"name": "success", "type": "bool"}],
        "type": "function"
    }
]

# Global variables for configuration
okx_api_key = ''
okx_secret = ''
okx_passphrase = ''
slippage = 0.01
wait_account_min = 10
wait_account_max = 20
gas_limit = None  # 默认None，使用120%缓冲
tx_timeout = 10  # 默认交易确认超时（秒）
max_retries = 3  # 默认重试次数
is_running = False
current_token_address = None
current_target_address = None
chain_config = None
w3 = None  # 动态初始化
networks = DEFAULT_NETWORKS  # 从 config 加载

# Stats file
STATS_FILE = 'trade_stats.json'

# 存储已授权地址的缓存
approved_addresses = {}

# 获取当前估算 gas limit 的函数
def get_estimated_gas_limit(network):
    try:
        if network == "op":
            rpc = networks["op"]["rpc_url"]
        elif network == "base":
            rpc = networks["base"]["rpc_url"]
        else:
            return "计算失败 (留空使用实时gas的120%)"
        
        w3 = Web3(Web3.HTTPProvider(rpc))
        if w3.is_connected():
            # 使用有效的 dummy calldata（从参考程序移植，模拟 vote/swap 操作）
            dummy_data = '0x7ac09bf70000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000010000000000000000000000004dc22588ade05c40338a9d9d95a6da9dcee68bcd6000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000056bc75e2d63100000'
            dummy_tx = {
                'to': '0x0000000000000000000000000000000000000000',  # dummy to 地址
                'value': 0,
                'data': dummy_data,
            }
            estimated_gas = w3.eth.estimate_gas(dummy_tx)
            return f"{estimated_gas} (留空使用实时gas的120%)"
        else:
            return "无法连接 (留空使用实时gas的120%)"
    except Exception as e:
        logging.error(f"Gas 估算失败: {e}")
        return "计算失败 (留空使用实时gas的120%)"

class TradingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OKX_DEX_API_V6")
        self.root.geometry("900x600")
        
        self.chain_var = tk.StringVar(value="base")  # 默认链
        
        self.setup_gui()
        self.load_config()
        
    def setup_gui(self):
        # 主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 配置区域
        config_frame = ttk.LabelFrame(main_frame, text="配置参数")
        config_frame.pack(fill='x', pady=(0, 10))
        
        self.setup_config_section(config_frame)
        
        # 控制按钮区域
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x', pady=(0, 10))
        
        self.setup_control_buttons(control_frame)
        
        # 状态统计区域
        stats_frame = ttk.LabelFrame(main_frame, text="交易统计")
        stats_frame.pack(fill='x', pady=(0, 10))
        
        self.setup_stats_section(stats_frame)
        
        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="运行日志")
        log_frame.pack(fill='both', expand=True)
        
        self.setup_log_section(log_frame)
        
    def setup_config_section(self, frame):
        # API配置 - 第一行
        api_frame = ttk.Frame(frame)
        api_frame.pack(fill='x', pady=5)
        
        ttk.Label(api_frame, text="API Key:").pack(side='left', padx=5)
        self.api_key_entry = ttk.Entry(api_frame, width=25, show='*')
        self.api_key_entry.pack(side='left', padx=5)
        
        ttk.Label(api_frame, text="Secret:").pack(side='left', padx=5)
        self.secret_entry = ttk.Entry(api_frame, width=25, show='*')
        self.secret_entry.pack(side='left', padx=5)
        
        ttk.Label(api_frame, text="Passphrase:").pack(side='left', padx=5)
        self.passphrase_entry = ttk.Entry(api_frame, width=10, show='*')
        self.passphrase_entry.pack(side='left', padx=5)
        
        # 交易参数配置 - 第二行（移除 Gas 限制）
        params_frame = ttk.Frame(frame)
        params_frame.pack(fill='x', pady=5)
        
        # 第一组参数
        ttk.Label(params_frame, text="滑点（%）:").pack(side='left', padx=5)
        self.slippage_entry = ttk.Entry(params_frame, width=5)
        self.slippage_entry.pack(side='left', padx=2)
        
        # 第二组参数
        ttk.Label(params_frame, text="地址间隔（秒）:").pack(side='left', padx=(15, 2))
        self.account_min_entry = ttk.Entry(params_frame, width=3)
        self.account_min_entry.pack(side='left', padx=2)
        ttk.Label(params_frame, text="-").pack(side='left', padx=2)
        self.account_max_entry = ttk.Entry(params_frame, width=3)
        self.account_max_entry.pack(side='left', padx=2)
        
        # 第三组参数 - 超时
        ttk.Label(params_frame, text="超时（秒）:").pack(side='left', padx=(15, 2))
        self.tx_timeout_entry = ttk.Entry(params_frame, width=5)
        self.tx_timeout_entry.pack(side='left', padx=2)
        
        # 第四组参数 - 重试次数
        ttk.Label(params_frame, text="重试次数:").pack(side='left', padx=(15, 2))
        self.max_retries_entry = ttk.Entry(params_frame, width=3)
        self.max_retries_entry.pack(side='left', padx=2)
        
        # 交易参数配置 - 第三行（代币和目标合约）
        params_frame2 = ttk.Frame(frame)
        params_frame2.pack(fill='x', pady=5)
        
        # 代币合约地址（可编辑）
        ttk.Label(params_frame2, text="代币合约:").pack(side='left', padx=5)
        self.token_contract_entry = ttk.Entry(params_frame2, width=38)
        self.token_contract_entry.pack(side='left', padx=2)
        
        # 目标代币合约地址（可编辑）
        ttk.Label(params_frame2, text="目标代币:").pack(side='left', padx=5)
        self.target_contract_entry = ttk.Entry(params_frame2, width=38)
        self.target_contract_entry.pack(side='left', padx=2)
        
        # 新增第四行：选择网络 + Gas Limit（如截图）
        params_frame3 = ttk.Frame(frame)
        params_frame3.pack(fill='x', pady=5)
        
        ttk.Label(params_frame3, text="选择网络:").pack(side='left', padx=5)
        
        self.chain_combo = ttk.Combobox(params_frame3, textvariable=self.chain_var, values=list(networks.keys()), state="readonly", width=10)
        self.chain_combo.pack(side='left', padx=5)
        self.chain_combo.bind("<<ComboboxSelected>>", self.update_default_contracts)
        
        ttk.Label(params_frame3, text="Gas Limit:").pack(side='left', padx=(15, 2))
        self.gas_limit_entry = ttk.Entry(params_frame3, width=8)
        self.gas_limit_entry.pack(side='left', padx=2)
        
        self.current_gas_label = ttk.Label(params_frame3, text="当前 Gas Limit: (建议留空，自动使用使用实时gas的120%)")
        self.current_gas_label.pack(side='left', padx=5)
        
    def update_default_contracts(self, event=None):
        """当链选择变化时，更新默认合约地址和 Gas Label"""
        selected_chain = self.chain_var.get()
        if selected_chain in networks:
            self.token_contract_entry.delete(0, tk.END)
            self.token_contract_entry.insert(0, networks[selected_chain]["default_token_address"])
            self.target_contract_entry.delete(0, tk.END)
            self.target_contract_entry.insert(0, networks[selected_chain]["default_target_address"])
            
            # 使用线程估算 Gas 以避免阻塞 UI
            threading.Thread(target=self.fetch_gas_limit, args=(selected_chain,)).start()
    
    def fetch_gas_limit(self, network):
        gas_limit_str = get_estimated_gas_limit(network)
        self.current_gas_label.config(text=f"当前 Gas Limit: {gas_limit_str}")
        
    def setup_control_buttons(self, frame):
        self.save_button = ttk.Button(frame, text="保存配置", command=self.save_config)
        self.save_button.pack(side='left', padx=5)
        
        self.start_button = ttk.Button(frame, text="开始运行", command=self.start_trading)
        self.start_button.pack(side='right', padx=5)
        
        self.stop_button = ttk.Button(frame, text="停止", command=self.stop_trading, state='disabled')
        self.stop_button.pack(side='right', padx=5)
        
    def setup_stats_section(self, frame):
        """设置交易统计区域"""
        stats_grid = ttk.Frame(frame)
        stats_grid.pack(fill='x', padx=10, pady=10)
        
        # 总统计
        ttk.Label(stats_grid, text="总交易次数:").grid(row=0, column=0, sticky='w', padx=5)
        self.total_txs_label = ttk.Label(stats_grid, text="0", foreground="blue")
        self.total_txs_label.grid(row=0, column=1, padx=5)
        
        ttk.Label(stats_grid, text="总卖出次数:").grid(row=0, column=2, sticky='w', padx=5)
        self.total_sells_label = ttk.Label(stats_grid, text="0", foreground="red")
        self.total_sells_label.grid(row=0, column=3, padx=5)
        
        # 当前地址统计
        ttk.Label(stats_grid, text="当前地址:").grid(row=1, column=0, sticky='w', padx=5)
        self.current_address_label = ttk.Label(stats_grid, text="未开始", foreground="purple")
        self.current_address_label.grid(row=1, column=1, padx=5)
        
        ttk.Label(stats_grid, text="当前卖出:").grid(row=1, column=2, sticky='w', padx=5)
        self.current_sells_label = ttk.Label(stats_grid, text="0")
        self.current_sells_label.grid(row=1, column=3, padx=5)
        
        # 刷新按钮
        refresh_btn = ttk.Button(stats_grid, text="刷新统计", command=self.refresh_stats)
        refresh_btn.grid(row=1, column=4, padx=10)
        
    def setup_log_section(self, frame):
        self.log_text = scrolledtext.ScrolledText(frame, height=20, width=100)
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.log_text.config(state='disabled')
        
    def refresh_stats(self):
        """刷新统计信息"""
        try:
            stats = load_trade_stats()
            total_sells = sum(addr_stats['sells'] for addr_stats in stats.values())
            total_txs = total_sells
            
            self.total_txs_label.config(text=str(total_txs))
            self.total_sells_label.config(text=str(total_sells))
            
        except Exception as e:
            self.log_message(f"刷新统计错误: {e}")
            
    def update_current_address_stats(self, address, sells):
        """更新当前地址统计"""
        short_address = f"{address[:6]}...{address[-4:]}"
        self.current_address_label.config(text=short_address)
        self.current_sells_label.config(text=str(sells))
        
    def log_message(self, message):
        self.log_text.config(state='normal')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_text.insert('end', f"{timestamp} - {message}\n")
        self.log_text.see('end')
        self.log_text.config(state='disabled')
        
    def load_config(self):
        global networks
        try:
            if os.path.exists('config.json'):
                with open('config.json', 'r') as f:
                    config = json.load(f)
                    
                self.api_key_entry.insert(0, config.get('api_key', ''))
                self.secret_entry.insert(0, config.get('secret', ''))
                self.passphrase_entry.insert(0, config.get('passphrase', ''))
                self.slippage_entry.insert(0, str(config.get('slippage', 0.01)))
                self.account_min_entry.insert(0, str(config.get('wait_account_min', 10)))
                self.account_max_entry.insert(0, str(config.get('wait_account_max', 20)))
                self.tx_timeout_entry.insert(0, str(config.get('tx_timeout', 10)))
                self.max_retries_entry.insert(0, str(config.get('max_retries', 3)))
                # 默认留空 Gas Limit
                self.gas_limit_entry.insert(0, '')
                
                # 加载 networks
                networks = config.get('networks', DEFAULT_NETWORKS)
                
                # 更新Combobox values
                self.chain_combo['values'] = list(networks.keys())
                
                # 加载链并更新默认
                chain = config.get('chain', 'base')
                if chain in networks:
                    self.chain_var.set(chain)
                else:
                    self.chain_var.set(list(networks.keys())[0] if networks else 'base')
                self.update_default_contracts()
                
                self.token_contract_entry.delete(0, tk.END)
                self.token_contract_entry.insert(0, config.get('token_contract', networks[self.chain_var.get()]["default_token_address"]))
                self.target_contract_entry.delete(0, tk.END)
                self.target_contract_entry.insert(0, config.get('target_contract', networks[self.chain_var.get()]["default_target_address"]))
                
                self.refresh_stats()
                
        except Exception as e:
            self.log_message(f"加载配置错误: {e}")
            
    def save_config(self):
        try:
            config = {
                'api_key': self.api_key_entry.get(),
                'secret': self.secret_entry.get(),
                'passphrase': self.passphrase_entry.get(),
                'slippage': float(self.slippage_entry.get()),
                'wait_account_min': int(float(self.account_min_entry.get())),
                'wait_account_max': int(float(self.account_max_entry.get())),
                'tx_timeout': int(float(self.tx_timeout_entry.get())),
                'max_retries': int(float(self.max_retries_entry.get())),
                'chain': self.chain_var.get(),
                'token_contract': self.token_contract_entry.get(),
                'target_contract': self.target_contract_entry.get(),
                'networks': networks  # 保存 networks
            }
            
            with open('config.json', 'w') as f:
                json.dump(config, f, indent=4)
                
            self.log_message("配置保存成功!")
            
        except ValueError as e:
            messagebox.showerror("错误", f"参数格式错误: {e}")
        except Exception as e:
            self.log_message(f"保存配置错误: {e}")
            
    def start_trading(self):
        global is_running, okx_api_key, okx_secret, okx_passphrase, current_token_address, current_target_address
        global slippage, wait_account_min, wait_account_max, gas_limit, tx_timeout, max_retries
        global chain_config, w3
        
        try:
            # 获取配置参数
            okx_api_key = self.api_key_entry.get()
            okx_secret = self.secret_entry.get()
            okx_passphrase = self.passphrase_entry.get()
            slippage = float(self.slippage_entry.get())
            wait_account_min = int(float(self.account_min_entry.get()))
            wait_account_max = int(float(self.account_max_entry.get()))
            tx_timeout = int(float(self.tx_timeout_entry.get()))
            max_retries = int(float(self.max_retries_entry.get()))
            
            # Gas Limit: 如果空，用None（使用120%缓冲）
            gas_limit_str = self.gas_limit_entry.get().strip()
            if gas_limit_str:
                gas_limit = int(float(gas_limit_str))
            else:
                gas_limit = None
            
            # 获取链配置
            selected_chain = self.chain_var.get()
            if selected_chain not in networks:
                messagebox.showerror("错误", "无效的链选择")
                return
            chain_config = networks[selected_chain]
            
            # 初始化Web3
            w3 = Web3(Web3.HTTPProvider(chain_config['rpc_url']))
            
            # 获取代币合约地址
            token_contract_str = self.token_contract_entry.get().strip()
            if not token_contract_str:
                messagebox.showerror("错误", "请输入代币合约地址")
                return
                
            try:
                current_token_address = Web3.to_checksum_address(token_contract_str)
            except ValueError:
                messagebox.showerror("错误", "无效的代币合约地址格式")
                return
            
            # 获取目标代币合约地址
            target_contract_str = self.target_contract_entry.get().strip()
            if not target_contract_str:
                messagebox.showerror("错误", "请输入目标代币合约地址")
                return
                
            try:
                current_target_address = Web3.to_checksum_address(target_contract_str)
            except ValueError:
                messagebox.showerror("错误", "无效的目标代币合约地址格式")
                return
            
            # 检查API配置
            if not all([okx_api_key, okx_secret, okx_passphrase]):
                messagebox.showerror("错误", "请填写完整的OKX API配置")
                return
            
            # 检查地址文件是否存在
            if not os.path.exists('address.txt'):
                messagebox.showerror("错误", "找不到 address.txt 文件")
                return
                
            is_running = True
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.save_button.config(state='disabled')
            
            # 在后台线程中运行交易
            self.trading_thread = threading.Thread(target=self.run_trading, daemon=True)
            self.trading_thread.start()
            
            gas_msg = "实时gas的120%" if gas_limit is None else str(gas_limit)
            self.log_message(f"交易开始运行（链: {selected_chain}，Gas Limit: {gas_msg}）...")
            
        except ValueError as e:
            messagebox.showerror("错误", f"参数格式错误: {e}")
        except Exception as e:
            messagebox.showerror("错误", f"启动失败: {e}")
            
    def stop_trading(self):
        global is_running
        is_running = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.save_button.config(state='normal')
        self.log_message("交易停止中...")
        
    def run_trading(self):
        """在后台线程中运行交易逻辑"""
        try:
            main(self.log_message, self.update_current_address_stats, self.refresh_stats)
        except Exception as e:
            self.log_message(f"交易运行错误: {e}")
        finally:
            self.root.after(0, self.on_trading_stopped)
            
    def on_trading_stopped(self):
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.save_button.config(state='normal')
        self.log_message("交易已停止")

# 交易函数
def load_trade_stats():
    if os.path.exists(STATS_FILE):
        with open(STATS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_trade_stats(stats):
    with open(STATS_FILE, 'w') as f:
        json.dump(stats, f, indent=4)

def get_quote(params):
    try:
        api_url = 'https://web3.okx.com/api/v6/dex/aggregator/quote'
        timestamp = datetime.datetime.utcnow().isoformat(timespec='milliseconds') + 'Z'
        query_string = urllib.parse.urlencode(params)
        request_path = '/api/v6/dex/aggregator/quote?' + query_string
        message = timestamp + 'GET' + request_path
        sign = base64.b64encode(hmac.new(okx_secret.encode(), message.encode(), hashlib.sha256).digest()).decode()
        headers = {
            'OK-ACCESS-KEY': okx_api_key,
            'OK-ACCESS-SIGN': sign,
            'OK-ACCESS-TIMESTAMP': timestamp,
            'OK-ACCESS-PASSPHRASE': okx_passphrase,
            'Content-Type': 'application/json'
        }

        full_url = f"{api_url}?{query_string}"
        response = requests.get(full_url, headers=headers)
        resp = response.json()
        if resp.get('code') != '0':
            raise ValueError(f"Quote API error: {resp.get('msg')}")
        return resp
    except Exception as e:
        logging.error(f"Error in get_quote: {e}")
        raise

def get_swap_data(params):
    try:
        api_url = 'https://web3.okx.com/api/v6/dex/aggregator/swap'
        timestamp = datetime.datetime.utcnow().isoformat(timespec='milliseconds') + 'Z'
        query_string = urllib.parse.urlencode(params)
        request_path = '/api/v6/dex/aggregator/swap?' + query_string
        message = timestamp + 'GET' + request_path
        sign = base64.b64encode(hmac.new(okx_secret.encode(), message.encode(), hashlib.sha256).digest()).decode()
        headers = {
            'OK-ACCESS-KEY': okx_api_key,
            'OK-ACCESS-SIGN': sign,
            'OK-ACCESS-TIMESTAMP': timestamp,
            'OK-ACCESS-PASSPHRASE': okx_passphrase,
            'Content-Type': 'application/json'
        }

        full_url = f"{api_url}?{query_string}"
        response = requests.get(full_url, headers=headers)
        resp = response.json()
        if resp.get('code') != '0':
            raise ValueError(f"Swap API error: {resp.get('msg')}")
        return resp
    except Exception as e:
        logging.error(f"Error in get_swap_data: {e}")
        raise

def get_approve_data(chain_index, token_address, approve_amount='115792089237316195423570985008687907853269984665640564039457584007913129639935'):
    try:
        api_url = 'https://web3.okx.com/api/v6/dex/aggregator/approve-transaction'
        params = {
            'chainIndex': chain_index,
            'tokenContractAddress': token_address,
            'approveAmount': approve_amount
        }
        timestamp = datetime.datetime.utcnow().isoformat(timespec='milliseconds') + 'Z'
        query_string = urllib.parse.urlencode(params)
        request_path = '/api/v6/dex/aggregator/approve-transaction?' + query_string
        message = timestamp + 'GET' + request_path
        sign = base64.b64encode(hmac.new(okx_secret.encode(), message.encode(), hashlib.sha256).digest()).decode()
        headers = {
            'OK-ACCESS-KEY': okx_api_key,
            'OK-ACCESS-SIGN': sign,
            'OK-ACCESS-TIMESTAMP': timestamp,
            'OK-ACCESS-PASSPHRASE': okx_passphrase,
            'Content-Type': 'application/json'
        }

        full_url = f"{api_url}?{query_string}"
        response = requests.get(full_url, headers=headers)
        resp = response.json()
        if resp.get('code') != '0':
            raise ValueError(f"Approve API error: {resp.get('msg')}")
        return resp
    except Exception as e:
        logging.error(f"Error in get_approve_data: {e}")
        raise

def ensure_tx_fields(tx_dict, default_gas=400000):
    tx = tx_dict.copy()
    if 'gas' not in tx:
        tx['gas'] = default_gas
    if 'value' not in tx:
        tx['value'] = 0
    return tx

def build_and_send_tx(tx_dict, account, log_callback=None):
    global tx_timeout, max_retries
    for attempt in range(max_retries):
        try:
            # 获取当前gas费用
            gas_attempt = 0
            while gas_attempt < 3:
                try:
                    fee_history = w3.eth.fee_history(10, 'latest')
                    base_fee_estimates = fee_history['baseFeePerGas']
                    base_fee = base_fee_estimates[-1]  # Estimated next base fee
                    max_priority_fee = w3.eth.max_priority_fee
                    max_fee_per_gas = base_fee + (max_priority_fee * 2)
                    break  # Success, exit loop
                except Exception as gas_e:
                    gas_attempt += 1
                    if log_callback:
                        log_callback(f"Gas estimation failed (attempt {gas_attempt}/3): {gas_e}. Retrying...")
                    time.sleep(2)
                if gas_attempt == 3:
                    raise ValueError("Failed to estimate gas after retries")

            tx = ensure_tx_fields(tx_dict)
            original_gas = tx['gas']
            buffered_gas = min(int(original_gas * 1.2), 40000000)
            tx['gas'] = buffered_gas
            
            if log_callback:
                log_callback(f"Gas设置: {original_gas} -> {buffered_gas} (+20%)")
            
            # 更新交易参数
            tx.update({
                'nonce': w3.eth.get_transaction_count(account.address, 'pending'),
                'chainId': chain_config['chain_id'],
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee,
            })

            if log_callback:
                log_callback(f"发送交易...")
            
            # 签名并发送交易
            signed_tx = account.sign_transaction(tx)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            if log_callback:
                log_callback(f"交易已发送，等待确认: {tx_hash.hex()}")
            
            # 等待交易确认
            start_time = time.time()
            while time.time() - start_time < tx_timeout:
                try:
                    receipt = w3.eth.get_transaction_receipt(tx_hash)
                    if receipt is not None:
                        if receipt['status'] == 1:
                            if log_callback:
                                log_callback(f"交易成功确认: {tx_hash.hex()}")
                            return receipt, tx_hash.hex()
                        else:
                            raise ValueError(f"交易失败: {tx_hash.hex()}")
                except:
                    time.sleep(2)
            
            raise TransactionNotFound("交易确认超时")
            
        except Exception as e:
            if attempt < max_retries - 1:
                if log_callback:
                    log_callback(f"交易尝试 {attempt+1}/{max_retries} 失败: {e}, 等待重试...")
                time.sleep(5)
            else:
                if log_callback:
                    log_callback(f"交易最终失败: {e}")
                raise

def check_allowance(token_address, account, spender):
    try:
        contract = w3.eth.contract(address=token_address, abi=ERC20_ABI)
        allowance = contract.functions.allowance(account.address, spender).call()
        return allowance > 2**256 - 1000
    except Exception as e:
        logging.error(f"Error checking allowance: {e}")
        return False

def approve_token(token_address, account, spender, log_callback=None):
    try:
        # 检查是否已经授权
        if check_allowance(token_address, account, spender):
            if log_callback:
                log_callback(f"已授权，跳过授权步骤")
            return True

        # 获取授权数据
        approve_resp = get_approve_data(str(chain_config['chain_id']), token_address)
        tx_data = approve_resp['data'][0]
        
        if log_callback:
            log_callback(f"执行授权操作")
        
        # 构建授权交易
        tx = {
            'to': token_address,
            'data': tx_data['data'],
            'value': 0,
        }
        if gas_limit is not None:
            tx['gas'] = gas_limit
        
        # 发送授权交易
        receipt, tx_hash = build_and_send_tx(tx, account, log_callback)
        if tx_hash:
            if log_callback:
                log_callback(f"授权成功: {tx_hash}")
            time.sleep(2)  # 等待授权确认
            return True
        return False
        
    except Exception as e:
        if log_callback:
            log_callback(f"授权错误: {e}")
        return False

def perform_swap(params, from_token, account, log_callback=None):
    try:
        if log_callback:
            log_callback("获取报价...")
        
        # 获取报价
        quote_resp = get_quote(params)
        if not quote_resp.get('data'):
            raise ValueError("获取报价数据失败")

        # 准备交换参数
        swap_params = {
            'chainIndex': str(chain_config['chain_id']),
            'fromTokenAddress': params['fromTokenAddress'],
            'toTokenAddress': params['toTokenAddress'],
            'amount': params['amount'],
            'slippagePercent': str(slippage * 100),
            'userWalletAddress': params['userAddr'],
            'priceImpactProtectionPercent': '90',  # V6 新参数，默认90%
            'swapMode': 'exactIn'  # 默认
        }
        
        if log_callback:
            log_callback("获取交换数据...")
        
        # 获取交换数据
        swap_resp = get_swap_data(swap_params)
        
        if not swap_resp.get('data'):
            raise ValueError("获取交换数据失败")
            
        # 获取spender地址
        spender_address = Web3.to_checksum_address(swap_resp['data'][0]['tx']['to'])

        # 执行授权
        approve_success = approve_token(from_token, account, spender_address, log_callback)
        if not approve_success:
            raise ValueError("授权失败")

        # 获取交易数据
        tx_data = swap_resp['data'][0]['tx']
        to_address = Web3.to_checksum_address(tx_data['to'])
        calldata = tx_data['data']
        value = int(tx_data['value'], 0)

        # 构建交换交易
        tx = {
            'to': to_address,
            'data': calldata,
            'value': value,
        }
        if gas_limit is not None:
            tx['gas'] = gas_limit
        elif 'gas' in tx_data:
            tx['gas'] = int(tx_data['gas'])
        
        if log_callback:
            log_callback("执行交换交易...")
        
        # 发送交换交易
        receipt, tx_hash = build_and_send_tx(tx, account, log_callback)
        if tx_hash:
            return True, tx_hash
        return False, None
        
    except Exception as e:
        if log_callback:
            log_callback(f"交换错误: {e}")
        return False, None

def main(log_callback=None, update_stats_callback=None, refresh_stats_callback=None):
    global current_token_address, current_target_address, is_running, chain_config
    
    if log_callback:
        log_callback("开始执行交易流程")
    
    # 创建合约实例
    token_contract = w3.eth.contract(address=current_token_address, abi=ERC20_ABI)
    
    # 加载交易统计
    trade_stats = load_trade_stats()

    try:
        # 读取地址文件
        with open('address.txt', 'r') as f:
            priv_keys = []
            for line in f:
                clean_key = line.strip().lstrip('0x').lower()
                if clean_key and len(clean_key) == 64 and all(c in '0123456789abcdef' for c in clean_key):
                    priv_keys.append(clean_key)
        
        if log_callback:
            log_callback(f"成功加载 {len(priv_keys)} 个有效私钥")
        
        # 随机打乱地址顺序
        random.shuffle(priv_keys)

        # 处理每个地址
        for priv_key in priv_keys:
            if not is_running:
                break

            # 创建账户对象
            account = w3.eth.account.from_key(priv_key)
            address = account.address
            
            if log_callback:
                log_callback(f"处理地址: {address[:6]}...{address[-4:]}")
            
            # 初始化统计
            if address not in trade_stats:
                trade_stats[address] = {'sells': 0, 'total': 0}
            
            # 更新界面统计
            if update_stats_callback:
                update_stats_callback(address, trade_stats[address]['sells'])

            # 检查ETH余额是否足够支付Gas
            eth_balance = w3.eth.get_balance(address)
            if eth_balance < 0.001 * 10**18:
                if log_callback:
                    log_callback(f"ETH余额不足，跳过: {eth_balance/10**18:.6f} ETH")
                continue

            # 检查代币余额
            token_balance = token_contract.functions.balanceOf(address).call()
            if token_balance > 0:
                if log_callback:
                    log_callback(f"代币余额: {token_balance}，准备卖出")
                
                # 执行卖出交易
                params_sell = {
                    'chainIndex': str(chain_config['chain_id']),
                    'fromTokenAddress': current_token_address,
                    'toTokenAddress': current_target_address,
                    'amount': str(token_balance),
                    'userAddr': address,
                }
                try:
                    sell_success, sell_tx_hash = perform_swap(params_sell, current_token_address, account, log_callback)
                    if sell_success and sell_tx_hash:
                        # 更新卖出统计
                        trade_stats[address]['sells'] += 1
                        trade_stats[address]['total'] += 1
                        
                        if log_callback:
                            log_callback(f"✅ 卖出成功: {sell_tx_hash}")
                        
                        # 更新界面统计
                        if update_stats_callback:
                            update_stats_callback(address, trade_stats[address]['sells'])
                        
                        if refresh_stats_callback:
                            refresh_stats_callback()
                except Exception as e:
                    if log_callback:
                        log_callback(f"卖出交易失败: {e}")
            else:
                if log_callback:
                    log_callback("无代币余额，跳过卖出")
            
            # 保存统计信息
            save_trade_stats(trade_stats)
            
            # 更新总统计
            if refresh_stats_callback:
                refresh_stats_callback()
            
            # 等待一段时间处理下一个地址
            wait_time = random.uniform(wait_account_min, wait_account_max)
            if log_callback:
                log_callback(f"等待 {wait_time:.1f} 秒后处理下一个地址...")
            time.sleep(wait_time)

    except Exception as e:
        if log_callback:
            log_callback(f"处理过程中出现错误: {e}")

    if log_callback:
        log_callback("交易流程结束")

if __name__ == '__main__':
    root = tk.Tk()
    app = TradingApp(root)
    root.mainloop()
