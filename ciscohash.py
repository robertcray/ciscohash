#!/usr/bin/python

#
# Look for passwords in Cisco configuration files
# Decode any type 7 hashes we find
# Try to decode any type 5 hashes based on the already
# decoded type 7 hashes, as well as an optional word
# list.
#
# Robert Cray
# 8/2011

import sys
import argparse
import re
import crypt

# Decode bogus Cisco hash
def hash7(hash):
  xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
          0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
	  0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
          0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36,
          0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76,
          0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b,
          0x3b, 0x66, 0x67, 0x38, 0x37 ];
  if (len(hash)&1 == 1):
    return None		# Odd length of hash
  m = re.search('^(..)(.+)', hash)
  if m:
    (s, e) = (int(m.group(1)), m.group(2))
  else:
    return None
  result = ''
  for c in re.findall('[\da-fA-F]{2}', e):
    result = result + ("%c" % (int(c, 16) ^ xlat[s]))
    s = s + 1
  return result

#
# See if we can decrypt any type 5 hashes by using
# the already decrypted type 5 hashes
#
# If the "--dict" argument was passed - try all the
# potential passwords in that list
#
def check_t5(type5, t7pass, dict):
  found = set()
  for h in type5:
    salt = '$1$' + h[3:7]
    fnd = False
    for p in t7pass:
      nh = crypt.crypt(p, salt)
      if nh == h:
        found.add(h + ':' + p)
        fnd = True
        break
    if dict != None and not fnd:
      dict.seek(0)
      for p in dict:
        nh = crypt.crypt(p.rstrip(), salt)
        if nh == h:
          found.add(h + ':' + p.rstrip())
          break
  return found

#
# Process each file given on the command line
# 
def process_file(file, hp, allpass, type5):
  try:
    fd = open(file, 'r')
  except:
    print >>sys.stderr, "Could not open %s" % file
    return 0
  for line in fd:
    m = re.search(r'secret 5 (\$1\$.*)', line)
    if m:
      type5.add(m.group(1))
    for ptype in hp:
      m = re.search(ptype[1], line)
      if m:
        dc = hash7(m.group(1))
        ptype[2].add(dc)
        allpass.add(dc)
        break
  fd.close()
  return 1

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Cisco Hash')
  parser.add_argument('configfiles', metavar='configfile', type=str, nargs='+',
	help='List of Cisco Config Files')
  parser.add_argument('--dict', '-d', metavar='dict', type=argparse.FileType('r'), nargs='?')
  parser.add_argument('--verbose', '-v', action='store_true')
  parser.add_argument('--quiet', '-q', action='store_true')
  parser.add_argument('--output', '-o', metavar='outputfile', type=argparse.FileType('w'),
	nargs='?', default=sys.stdout)

  args = parser.parse_args()


  # List of lists
  # (1) type of password
  # (2) Regex to match on (compiled)
  # (3) A set to put passwords into...
  ptypes = [
    ['enable', r'enable password 7 ([\da-fA-F]+)', set()],
    ['httppass', re.compile(r'ip http client password 7 ([\da-fA-F]+)'), set()],
    ['ftpass', re.compile(r'ip ftp password 7 ([\da-fA-F]+)'), set()],
    ['userpass', re.compile(r'username.*password 7 ([\da-fA-F]+)'), set()],
    ['neighbor', re.compile(r'neighbor \d+\.\d+\.\d+\.\d+ password 7 ([\da-fA-F]+)'), set()],
    ['line', re.compile(r'password 7 ([\da-fA-F]+)'), set()],
    ['tacacs', re.compile(r' key 7 ([\da-fA-F]+)'), set()],
    ['wpa', re.compile(r' ascii 7 ([\da-fA-F]+)'), set()],
  ]

  allpass = set()
  type5 = set()

  for file in args.configfiles:
    process_file(file, ptypes, allpass, type5)

  print >>args.output, "Found total of %d passwords" % len(allpass)
  for pt in ptypes:
    if len(pt[2]) == 0:
      continue
    print >>args.output, "%s passwords (%d)" % (pt[0], len(pt[2]))
    if not args.quiet:
      for p in pt[2]:
        print >>args.output, "  %s" % p

  t5d = check_t5(type5, allpass, args.dict)
  if len(t5d) > 0:
    print >>args.output, "Decrypted Type 5 passwords (%d)" % len(t5d)
    for p in t5d:
      print >>args.output, "  %s" % p

  sys.exit(0)
