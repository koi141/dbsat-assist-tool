## 概要

- DBSATの補助ツール郡
- DBSATのレポートは機密情報が詰まっているので取り扱いには注意すること

## `get_cvss.py`

- NIST NVD APIから情報を取得。  
    - https://nvdlib.com/en/latest/

### 前準備
- `input_file`として、`report/cve.csv`にCVEのリストをCSV形式で置いておく必要がある
    - 例:
    ```csv
    CVE-2021-44228, CVE-2023-4863, CVE-2017-0144
    ```

- API Keyは使用していない
    - API Keyがない場合は6秒待機が必要なので、出力はそこまで早くない。というよりめっちゃ遅い。
    - API Keyは以下から取得することができる  
        - https://nvd.nist.gov/developers/request-an-api-key  
        - 無料のAPI Keyを取得している場合は delay=0.6 に短縮できるらしい

- CVSS v3.1 -> v3.0 -> v2 の順でスコアを探して取得している
```python
if hasattr(r, 'v31score'):
    score = r.v31score
    severity = r.v31severity
elif hasattr(r, 'v30score'):
    score = r.v30score
    severity = r.v30severity
elif hasattr(r, 'v2score'):
    score = r.v2score
    severity = r.v2severity
else:
    score = "N/A"
    severity = "Unknown"
```


### 実行
```shell
uv run get_cvss.py 
```

- 実行例
```shell
$ uv run get_cvss.py 
CVE ID          | Score | Version | Severity
--------------------------------------------------
CVE-2021-44228  | 10.0  | v3.1    | CRITICAL 
CVE-2023-4863   | 8.8   | v3.1    | HIGH 
CVE-2017-0144   | 8.8   | v3.1    | HIGH 
Done. Results saved to: output/cvss_result.txt
```

- 結果は `output/cvss_result.txt` に保存される
