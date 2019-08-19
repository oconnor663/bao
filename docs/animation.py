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
    char_by_char(s + "\n", "yellow")
    prompt()
    time.sleep(1)


def prompt():
    print(termcolor.colored("$ ", "blue"), end="")
    sys.stdout.flush()


def shell_out(command):
    subprocess.run(["zsh", "-c", command])


def time_hash(exe):
    char_by_char("time ")
    char_by_char(exe, "red")
    char_by_char(" " + TARGET)
    print()
    command = "time " + exe + " " + TARGET
    shell_out(command)
    time.sleep(1)


def main():
    comment("# Start with a 1 GiB file.")

    head_command = "ls -lh " + TARGET
    char_by_char(head_command + "\n")
    shell_out(head_command)
    time.sleep(1)

    comment("\n# See how long it takes to hash it with SHA-512.")

    time_hash("sha512sum")

    comment("\n# Now install Bao and see how long Bao takes to hash it.")

    char_by_char("cargo install bao_bin\n")
    prompt()
    time.sleep(1)

    time_hash("bao hash")


if __name__ == "__main__":
    main()
