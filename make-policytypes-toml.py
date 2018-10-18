#!/usr/bin/env python
# encoding: utf-8

"""
This file is to be run every once in a while[1] to ensure we align with
Firefox's representation of content policy types.

These constants are not expected to change a lot but at some time we might
want to move this into a build script written in Rust:
https://doc.rust-lang.org/cargo/reference/build-scripts.html#case-study-building-some-native-code


"""

import requests
import re

regextypedef = re.compile(r'\s+const\s+nsContentPolicyType\s+(\w+)\s*=\s*([0-9]+)')

URL = 'https://hg.mozilla.org/mozilla-central/raw-file/tip/dom/base/nsIContentPolicy.idl'
OUTFILE = open("src/policytypes.in", "w")
HEAD = "[\n";
FOOT = "];"



resp = requests.get(URL)

n = 0
OUTFILE.write(HEAD)
for typename, number in re.findall(regextypedef, resp.text):
    print n, number
    #assert int(n) == int(number)
    n += 1
    OUTFILE.write('    "{}",\n'.
                  format(typename,))

OUTFILE.write(FOOT)
OUTFILE.close()


