# Cowrie Log Parser

## Summary

此工具旨在將 [Cowrie](https://github.com/cowrie/cowrie) 所自動產生的 Log 檔（var/log/cowrie/cowrie.json）轉換為特定格式。

## Format

{session_id}/{ISO 8601 datetime}/{src_ip}:{src_port}/{operation}/{else infomation}

### Operation

-   connect
-   loginSuccess
-   loginFailed
-   command
-   commandFailed
-   sensitiveFiles

## Usage

```
python3 ./parser.py ./cowrie.json ./files.txt
```

第一個參數為 log 的檔案名稱；第二個參數為敏感資料的清單。

執行完畢後會輸出一個 "result.txt" 的檔案，即為執行結果。
