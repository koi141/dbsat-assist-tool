import nvdlib
import time
import read_csv_list

def get_cvss_scores(cve_list):
    print(f"{'CVE ID':<15} | {'Score':<5} | {'Version':<7} | {'Severity'}")
    print("-" * 50)

    with open(output_file, mode='w', encoding='utf-8') as f:

        header = "CVE ID\tScore\tSeverity"
        f.write(header + "\n")

        for cve_id in cve_list:
            try:
                results = nvdlib.searchCVE(cveId=cve_id)
                
                if not results:
                    print(f"{cve_id:<15} | Not Found")
                    continue

                r = results[0]
                
                if hasattr(r, 'v31score'):
                    score = r.v31score
                    severity = r.v31severity
                    version = 'v3.1'
                elif hasattr(r, 'v30score'):
                    score = r.v30score
                    severity = r.v30severity
                    version = 'v3.0'
                elif hasattr(r, 'v2score'):
                    score = r.v2score
                    severity = r.v2severity
                    version = 'v2'
                else:
                    score = "N/A"
                    severity = "Unknown"
                    version = 'Unknown'

                line = f"{cve_id:<15} | {score:<5} | {version:<7} | {severity} "
                f.write(line + "\n")

                print(line)

            except Exception as e:
                print(f"{cve_id:<15} | Error: {e}")
        
        print(f"Done. Results saved to: {output_file}")

if __name__ == "__main__":

    input_cve = "report/cve.csv"
    output_file = "output/cvss_result.txt"

    # CSVファイルからCVEリストを取得
    cve_list=read_csv_list.read_cve_from_csv(input_cve)

    # CSVリストからCVSSスコアを取得して表示
    get_cvss_scores(cve_list)
