import re
from collections import Counter


def check_concurency(threads_number):
    pattern = r"\{([^{}]*)\}"
    memory = {}
    matches = []
    with open("things.txt", "r") as file:
        lines = file.read()
        matches = re.findall(pattern, lines)
        # if matches[0] not in memory:
        #     memory[matches[0]] = [True, len(matches)]
        print(len(matches))
    memory = {}
    stop = 0
    for x in matches:
        if x not in memory:
            memory[x] = 1
        else:
            memory[x] += 1
    index = 0
    flag = True
    for x in memory:
        if memory[x] != threads_number:
            flag = False
        index += 1

    if flag == True:
        print("[+] the number of threads matches the number of updates to the key pair")
    else:
        print(
            "[-] the number of threads doesn't match the number of updates to the key pair"
        )


check_concurency(48)
