#! /usr/bin/python3

import time
import subprocess
import sys
import termcolor


TARGET = "/tmp/f"


def char_by_char(s, color=None):
    for c in s:
        if color is not None:
            c = termcolor.colored(c, color)
        time.sleep(0.03)
        print(c, end="")
        sys.stdout.flush()


def comment(s):
    char_by_char("# " + s + "\n", "yellow")


def prompt():
    print(termcolor.colored("$ ", "blue"), end="")
    sys.stdout.flush()


def shell_out(command):
    subprocess.run(["zsh", "-c", command])


def time_hash(exe):
    prompt()
    char_by_char("time ")
    char_by_char(exe, "red")
    char_by_char(" " + TARGET)
    print()
    command = "time " + exe + " " + TARGET
    shell_out(command)


def main():
    comment("Create a gigabyte file.")
    head_command = "head -c 1000000000 /dev/zero > " + TARGET
    prompt()
    char_by_char(head_command)
    print()
    shell_out(head_command)
    comment("Compare the time it takes for different programs to hash it.")
    time_hash("sha512sum")
    time_hash("md5sum")
    time_hash("sha1sum")
    time_hash("bao hash")


if __name__ == "__main__":
    main()
