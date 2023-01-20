import os
import sys

def load_logs(log_path):
    logs = {}
    lines = []

    with open(log_path, 'r') as f:
        lines = [line.rstrip() for line in f] 
        
    for line in lines:
        items = line.split('-')
        if len(items):
            logs[items[0]] = line

    return logs

def load_ids(id_path):
    ids = []
    bytes = []
    with open(id_path, mode="rb") as f:
        bytes = f.read()

    index = 0
    while index < len(bytes) - 9:
        if bytes[index] == 0x40 and  bytes[index+9] == 0x40:
            ids.append(str(int.from_bytes(bytes[index+1:index+9], "little")))
            index += 9
        else:
            index += 1

    return list(set(ids))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: python id2log.py /path/to/glibc/compilation/log /path/to/target/program/running/log")

    logs = load_logs(sys.argv[1])
    ids = load_ids(sys.argv[2])

    for id in ids:
        if id not in logs:
            print("wired: id is not found")
        else:
            print(logs[id])
