import sys
import math
from prng.index import prng
from cipher.index import cipher
from decipher.index import decipher
from hash.index import hash_file
from hmac_hash.index import hmac_hash

types = ["bytes", "int", "uuid"]
encs = ["ascii","utf8","utf-8","utf16le","utf-16le","ucs2","ucs-2","base64","base64url","latin1","binary","hex"]
args = sys.argv[1:]
options = {'size': 16, 'min': 0, 'max': 100, 'enc': 'hex', 'a': 'sha256'}

for i in range(0, len(args), 2):
    option_name = args[i].replace('--', '')
    if option_name in ["min","max","size"]:
        options[option_name] = int(args[i + 1])
    else:
        options[option_name] = args[i + 1]

if (options['ch'] == "prng"):
    print('Generate a random number\n',
        'Options:\n',
        'type:\t  [required]["bytes", "int", "uuid"]\n',
        'size:\t  [default: 16][number]\n',
        'min:\t  [default: 0][number]\n',
        'max:\t  [default: 100][number]\n',
        'enc:\t  [default: "hex"]["ascii","utf8","utf-8","utf16le","utf-16le","ucs2","ucs-2","base64","base64url","latin1","binary","hex"]')

    if options['type'] not in types or options['enc'] not in encs or math.isnan(options['size']) or math.isnan(options['min']) or math.isnan(options['max']):
        print('No choose option provided or params are not valid')
        print('Usage: python index.py --ch [required]')
        print('Values received:', options)
        sys.exit(1)

    print(prng(options['type'], options['size'], options['min'], options['max'], options['enc']))

elif (options['ch'] == "cipher"):
    print('Cifrar un archivo\n',
                'Flags requered :\n',
                'password: alias -p\t  ["String"]\n',
                'size:\t  \t[default: 128][128, 192, 256]\n',
                'salt:\t  \t[number]\n',
                'input:\t  alias -i\t ["String"]\n',
                'output:\t  alias -o\t ["String"]')

    if not options['p'] or not options['salt'] or math.isnan(options['size']) or not options['i'] or not options['o']:
        print('No choose option provided or params are not valid')
        print('Usage: python index.py --ch --p mypassword --size 256 --salt mysalt --i input.txt --o output.txt')
        print('Values received:', options)
        sys.exit(1)

    print(cipher(options['p'], options['size'], options['salt'], options['i'], options['o']))

elif (options['ch'] == "decipher"):
    print('File decipher\n',
                'Flags requered :\n',
                'password: alias -p\t  ["String"]\n',
                'size:\t  \t[default: 128][128, 192, 256]\n',
                'salt:\t  \t[number]\n',
                'input:\t  alias -i\t ["String"]\n',
                'output:\t  alias -o\t ["String"]')

    if not options['p'] or not options['salt'] or math.isnan(options['size']) or not options['i'] or not options['o']:
        print('No choose option provided or params are not valid')
        print('Usage: python index.py --ch --p mypassword --size 256 --salt mysalt --i input.txt --o output.txt')
        print('Values received:', options)
        sys.exit(1)

    print(decipher(options['p'], options['size'], options['salt'], options['i'], options['o']))
elif (options['ch'] == "hash"):
    print('Hash a file\n',
                'Flags requered :\n',
                'algorithm: alias -a\t  [default: "sha256"]["md5","sha1","sha256","sha512"]\n',
                'enc:\t  [default: "hex"]["base64","base64URL","hex","binary"]\n',
                'input: alias -i\t  \t["String"]\n')
    
    if not 'i' in options:
        print('No choose option provided or params are not valid')
        print('Usage: python index.py --ch --i path/inputText.txt')
        print('Values received:', options)
        sys.exit(1)

    print(hash_file(options['a'], options['i'], options['enc']))
elif (options['ch'] == "hmac"):
    print('Generate a HMAC for a file\n',
                  'Flags requered :\n',
                  'algorithm: alias -a\t  ["sha256"]["md5","sha1","sha256","sha512"]\n',
                  'enc:\t  [default: "hex"]["base64","base64URL","hex","binary"]\n',
                  'key: alias -k\t  ["String"]\n',
                  'input: alias -i\t  \t["String"]\n')
    
    if not 'i' in options or not 'k' in options:
        print('No choose option provided or params are not valid')
        print('Usage: python index.py --ch --i path/inputText.txt --k SecretKey')
        print('Values received:', options)
        sys.exit(1)

    print(hmac_hash(options['a'], options['k'], options['i'], options['enc']))

else:
    print('Selected option are invalid')
