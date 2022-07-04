import os
import csv
import pandas as pd
import re

def write_to_file(output, mode, line):
    with open(output, mode, newline='') as file:
        mywriter = csv.writer(file, delimiter=';')
        mywriter.writerow(line)


def scan_ip(pwd, result=[]):
    content = os.listdir(pwd)
    for files in content:
        # print(files)
        this_file = pwd + "\\" + files
        if os.path.isdir(this_file):
            scan_ip(this_file, result)
        if files.endswith("php") or files.endswith("txt") or files.endswith("html"):
            with open(this_file, "rb") as f:
                data = f.read()
                if b"geoplugin" in data:
                    # print("geoplugin", this_file)
                    result.extend(["geoplugin"])
                    return "geoplugin"
                elif b"ip-lookup" in data:
                    # print("ip-lookup", this_file)
                    result.extend(["ip-lookup"])
                    return "ip-lookup"
                elif b"extreme-ip" in data:
                    result.extend(["extreme-ip"])
                    # print("extreme-ip")
                    return "extreme-ip"
    return list(set(result))


def scan_redirect(pwd, result=[]):
    content = os.listdir(pwd)
    for files in content:
        # print(files)
        this_file = pwd + "\\" + files
        if os.path.isdir(this_file):
            scan_redirect(this_file, result)
        if files.endswith("php") or files.endswith("txt") or files.endswith("html"):
            with open(this_file, "rb") as f:
                data = f.read()
                if b"location" in data:
                    # print("location", this_file)
                    result.extend(["location"])
                    return "location"
                elif b"header" in data:
                    # print("header", this_file)
                    result.extend(["header"])
                    return "header"

    return list(set(result))


def scan_cloaking(pwd, result=[]):
    # Temp function, do better to find how similar of anti-ip and anti-bots
    content = os.listdir(pwd)
    for files in content:
        # print(files)
        this_file = pwd + "\\" + files
        if os.path.isdir(this_file):
            scan_cloaking(this_file, result)
        if "antibot" in files:
            # print("antibots")
            result.extend(["antibots"])
        # elif "anti" in files:
        #     result.extend(["anti something"])
        elif "blocker" in files:
            # print("blocker")
            result.extend(["blocker"])
        elif "bots" in files:
            # print("bots")
            result.extend(["bots"])

    return list(set(result))


def scan_contact(pwd, result=[]):
    content = os.listdir(pwd)
    for files in content:
        # print(files)
        this_file = pwd + "\\" + files
        if os.path.isdir(this_file):
            scan_contact(this_file, result)
        if files.endswith("php") or files.endswith("txt") or files.endswith("html"):
            with open(this_file, "rb") as f:
                data = f.read()
                if b"telegram" in data and b"email" in data:
                    # print("location", this_file)
                    result.extend(["telegram & email"])
                    return "telegram & email"
                if b"telegram" in data:
                    # print("location", this_file)
                    result.extend(["telegram"])
                    return "telegram"
                if b"email" in data:
                    # print("location", this_file)
                    result.extend(["email"])
                    return "email"

    return list(set(result))


def main():

    header = ["ip-lookup", "redirect", "cloaking", "submit_login", "contact", "rand&hash", "language"]
    # write_to_file("scan_kit.csv", "w", header)

    temp = 0
    with open("urls.txt", "r") as f:
        data = f.read()
        for url in data.split("\n"):
            # print(url)
            temp +=1
            url = url.replace(r"/", "\\")
            pwd = r"C:\Users\kahow\Desktop\GitHub\phishing_kits\May_2022" + url[7:-4:]
            pwd = r"C:\Users\kahow\Desktop\GitHub\phishing_kits\May_2022\amaz0n-support-team.duckdns.org (amazon%20(4).zip)"
            pwd = r"C:\Users\kahow\Desktop\GitHub\phishing_kits\May_2022\amaz0n-support-team.duckdns.org (Amazon%20by.zip)"
            print(pwd)

            f = [None, None, None, None, None, None, None]

            # f[0] = scan_ip(pwd)
            # f[1] = scan_redirect(pwd)
            # f[2] = scan_cloaking(pwd)
            # Temp function, do better to find how similar of anti-ip and anti-bots
            # f[3] = scan_contact(pwd)
            # f[4] =
            # f[5] =
            # f[6] =
            print(f)
            if temp == 1:
                return 1

main()

