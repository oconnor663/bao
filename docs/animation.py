#! /usr/bin/python3

# Note that when I run this script from my regular desktop, the numbers I get
# are 10% to 15% worse than when I run it under ideal conditions. To record
# bao_hash.cast, I disabled my Gnome desktop and rebooted my laptop with
# absolutely nothing else running. Asciinema is especially helpful here,
# because the desktop video capture that becomes bao_hash.gif takes a lot of
# CPU work, so the recording is of a replay rather than of the live event. Such
# is life with benchmarks. Though note that all the hash functions in the demo
# seem to benefit roughly equally from that pristine CPU environment.

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
