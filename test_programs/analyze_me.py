import os
import sys
import json as js
from pathlib import Path

name = "XRAY"
version = 0.3


def greet(message):
    print(message)


class Analyzer:
    def run(self):
        greet("XRAY is analyzing Python!")


greet(name)

analyzer = Analyzer()
analyzer.run()
