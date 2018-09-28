#! /usr/bin/python3

import time
import subprocess
import sys
import termcolor


TARGET = "/tmp/f"


def char_by_char(s):
    for c in s:
        time.sleep(0.03)
        print(c, end="")
        sys.stdout.flush()


def comment(s):
    char_by_char(termcolor.colored("# " + s + "\n", "yellow"))


def prompt():
    print(termcolor.colored("$ ", "blue"), end="")
    sys.stdout.flush()


def run_command(command):
    prompt()
    char_by_char(command)
    print()
    subprocess.run(["zsh", "-c", command])


def main():
    comment("Create a gigabyte file.")
    run_command("head -c 1000000000 /dev/zero > " + TARGET)
    comment("Compare the time it takes for different programs to hash it.")
    run_command("time md5sum " + TARGET)
    run_command("time sha512sum " + TARGET)
    run_command("time sha1sum " + TARGET)
    run_command("time bao hash " + TARGET)


if __name__ == "__main__":
    main()
