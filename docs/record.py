#! /usr/bin/python3

from os import path
from subprocess import run
import sys

HERE = path.dirname(__file__)
OUT = sys.argv[1]

run(["asciinema", "rec", OUT, "-c", path.join(HERE, "animation.py")])
