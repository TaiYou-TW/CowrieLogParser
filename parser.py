import sys
import json

result = ""
sources = {}
files = []

SPECIFY_FILE_LIST_FILENAME = "files.txt"
LOGS_FILENAME = "cowrie.json"
OUTPUT_FILENAME = "result.txt"


def find_sensitive_files(log):
    global files

    found_files = []
    commands = log["input"].split(" ")

    if len(commands) > 1:
        for idx in range(1, len(commands)):
            paths = commands[idx].split("/")
            counter = len(paths) - 1
            filename = paths[counter]
            while filename == "" and counter >= 0:
                counter -= 1
                filename = paths[counter]

            if filename != "" and filename in files:
                found_files.append(filename)

    return found_files


def classifier(log):
    global result, sources

    if log["eventid"] == "cowrie.login.failed":
        result += f"{log['session']}/{log['timestamp']}/{log['src_ip']}:{sources[log['session']]}/loginError/{{\"username\":\"{log['username']}\", \"password\":\"{log['password']}\"}}\n"
    elif log["eventid"] == "cowrie.login.success":
        result += f"{log['session']}/{log['timestamp']}/{log['src_ip']}:{sources[log['session']]}/loginSuccess/{{\"username\":\"{log['username']}\", \"password\":\"{log['password']}\"}}\n"
    elif log["eventid"] == "cowrie.command.failed":
        result += f"{log['session']}/{log['timestamp']}/{log['src_ip']}:{sources[log['session']]}/commandFailed/{log['input']}\n"
    elif log["eventid"] == "cowrie.command.input":
        result += f"{log['session']}/{log['timestamp']}/{log['src_ip']}:{sources[log['session']]}/command/{log['input']}\n"

        found_files = find_sensitive_files(log)
        if found_files:
            result += f"{log['session']}/{log['timestamp']}/{log['src_ip']}:{sources[log['session']]}/sensitiveFiles/{found_files}\n"

    elif log["eventid"] == "cowrie.session.connect":
        result += f"{log['session']}/{log['timestamp']}/{log['src_ip']}:{log['src_port']}/connect/{log['src_ip']}\n"
        sources[log["session"]] = log["src_port"]


if len(sys.argv) >= 2 and sys.argv[1]:
    LOGS_FILENAME = sys.argv[1]
if len(sys.argv) >= 3 and sys.argv[2]:
    SPECIFY_FILE_LIST_FILENAME = sys.argv[2]

with open(SPECIFY_FILE_LIST_FILENAME, mode="r") as f:
    lines = f.readlines()
    for line in lines:
        files.append(line.replace("\n", ""))
    f.close()

with open(LOGS_FILENAME, mode="r") as f:
    lines = f.readlines()
    for index in range(len(lines)):
        log = json.loads(lines[index])
        classifier(log)
    f.close()

with open(OUTPUT_FILENAME, mode="w") as f:
    f.write(result)
    f.close()

print("success!")