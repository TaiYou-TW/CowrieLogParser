# Cowrie Log Parser

## Summary

若有任何人進行連線等相關操作，Cowrie 則會將其記錄下來，此工具旨在將 [Cowrie](https://github.com/cowrie/cowrie) 所自動產生的 Log 檔（var/log/cowrie/cowrie.json）轉換為特定格式。

## Installation

1. 首先先依[官方教學](https://cowrie.readthedocs.io/en/latest/INSTALL.html)，將 Cowrie 安裝完畢並執行。
2. 下載此工具

## Requirements

Python3 at least 3.7.1

## Output Format

{session_id}/{ISO 8601 datetime}/{src_ip}:{src_port}/{operation}/{else infomation}

### Operation

- connect
- loginSuccess
- loginFailed
- command
- commandFailed
- sensitiveFiles

## Usage

```shell
$ python3 ./parser.py ./cowrie.json ./files.txt
success!
```

第一個參數為 cowrie 自動產生的 log 的檔案路徑；第二個參數為敏感資料的清單。

執行完畢後會輸出一個 "result.txt" 的檔案，即為執行結果。
