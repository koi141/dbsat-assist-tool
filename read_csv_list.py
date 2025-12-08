import csv
import os

# CSVファイルからCVEリストを読み込む
def read_cve_from_csv(filename):
    cve_list = []
    
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found.")
        return []

    try:
        with open(filename, mode='r', encoding='utf-8-sig') as f:
            reader = csv.reader(f)
            for row in reader:
                for item in row:
                    clean_item = item.strip()
                    if clean_item:
                        cve_list.append(clean_item)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return []
        
    return cve_list
