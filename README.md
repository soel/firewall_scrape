firewall_scrape
===============

## これは何?
ISG1000, FG300C のコンフィグから情報を抽出できます

## 主な特徴
- コンフィグの中身をエディタで確認する必要がありません
- MIP によるアドレス変換に対応

## インストール
1. 事前準備
  - perl v5.14.2 で動作確認しています
  
1. git clone
  ```bash
  git clone https://github.com/soel/firewall_scrape.git
  ```
  
## 使い方
- ISG1000 用
  ```bash
  ./fw.pl <address>
  ```

  表示例(アドレスは適当です)
  ```bash
  > ./fw.pl 8.8.8.8
  
  ------------------
  MIP:8.8.8.8
  Private:10.20.2.1
  
  ------------------
  ID:2150
  
  src-address:
  xxx.xxx.xxx.xxx/32, xxx.xxx.xxx.xxx/32
  
  service:
  SSH
  
  ------------------
  ID:1431
  
  src-address:
  Any-IPv4
  
  service:
  HTTP, HTTPS
  ```
  ```bash
  > ./fw.pl 10.20.2.1
  ```
  でも同じ結果が表示されます

- FG300C 用
  ```bash
  ./new_fw.pl <address>
  ```
  表示は ISG1000 用 と同じです
  
## その他情報
- destination は 1 つのみの対応です。複数の destination がある場合は表示できません

## ライセンス
- LICENSE.txt を御覧ください
- MIT ライセンスです

