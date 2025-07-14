#!/bin/bash
#start-ganache-and-save-keys

# 调试信息输出
set -x

# 启动 Ganache CLI 并将输出重定向到临时文件
OS=$(uname -s)

case "$OS" in
  Linux*)
    echo "Linux"
    ganache-cli --mnemonic "DAC" -l 90071992547 -e 1000 > ganache_output.txt &
    ;;
  Darwin*)
    echo "macOS"
    ganache-cli --mnemonic "DAC" -l 90071992547 -e 1000 > ganache_output.txt &
    ;;
  CYGWIN*|MINGW32*|MSYS*|MINGW*)
    echo "Windows"
    ;;
  *)
    echo "Unknown OS"
    ;;
esac

# 等待 Ganache CLI 完全启动
sleep 5

# 检查输出文件是否生成
if [ ! -f ganache_output.txt ] || [ ! -s ganache_output.txt ]; then
  echo "Error: ganache_output.txt not generated or is empty!"
  exit 1
fi

# 删除 .env 文件（如果存在）
[ -f .env ] && rm .env

# 调试输出文件内容
echo "ganache_output.txt content:"
cat ganache_output.txt

# 提取可用账户并写入到 .env 文件
i=1
cat ganache_output.txt | grep -A 12 'Available Accounts' | grep '0x' | while read -r line; do
  address=$(echo $line | awk '{print $2}')
  echo "ACCOUNT_$i=$address" >> .env
  ((i++))
done

# 读取私钥并写入到 .env 文件，去掉 '0x' 前缀
a=0
cat ganache_output.txt | grep 'Private Keys' -A 12 | grep -o '0x.*' | while read -r line; do
  echo "PRIVATE_KEY_$((++a))=${line:2}" >> .env
done

# 清理临时文件
rm ganache_output.txt

# 终止 Ganache 相关进程
pkill -f ganache-cli
