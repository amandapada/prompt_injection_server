import json
import re
from collections import Counter

def analyze_logs(log_file: str):
    blocked = 0
    processed = 0
    reasons = Counter()

    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            # Extract the JSON object from the log line (it’s prefixed by timestamp/level)
            m = re.search(r'(\{.*\})', line)
            if not m:
                continue
            try:
                entry = json.loads(m.group(1))
            except json.JSONDecodeError:
                continue

            status = entry.get("status")
            if status == "blocked":
                blocked += 1
                det = entry.get("detection_result", {})
                for reason in det.get("reasons", []):
                    reasons[reason] += 1
            elif status == "processed":
                processed += 1

    print(f"Total prompts: {blocked + processed}")
    print(f"Blocked: {blocked}")
    print(f"Processed: {processed}")
    print("\nReasons for blocking:")
    for reason, count in reasons.most_common():
        print(f"{reason}: {count}")

if __name__ == "__main__":
    analyze_logs("proxy_log.jsonl")
