from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.hashes import SHA1

import js

import getpass
import base64
import json
import time


DATA = """
F-J0an*rRG5&G+SlHmNBw8pvfQYm)cq`q*v_4pgk?mkiYnr^Nt@_pTx2ms}>{ySj6=nwM!hdx=4QLBjy
Hg(;a1(zpALTlp<Y9MT6x~PKOw7Fj+NX_T)f9x9NaHZj1r^MFSIw&?ZJVPc>6c0V7U5zx1%z`$v(kmo<
V^8kl-7qUNuPg-}wcFvRJts}AnJir^iq|G|DZnf<lj)Pctxom9oTF-bs)sy=o-U#dok}Ulda_Pud>82s
2rm#NI`FoV_-zazVx9sDC4<E}mPH+0lpwCdSO=;tjk$TvYzd}<ty>ERD$lal|G0hIMMo555gypOZn28L
siGC|*_>(P6_TNxBz`PJ;4#NiA=`^Fge%|(RE4);o~9hzam@@47b;jDDhwFLWZLlkZnY1m7r~82#@ZLr
zIge#4Lr>gAX`u48$kqeWQJ&bERwH%lzJ(TBLpx%j6%`s>eD2Z;V@Z-3}vnu%8U1i!pWI-GifuTIM>o7
qB=Z$aSY^~2nFx6^7#C}XA~>b;Q~@REMZ<{OgtAycK=zCr>|kW#u+wgDO1r{w6OCS4Yr|ud*;_jgZw$^
0JM36bV!?txy=x=8>|ZcqEun_#VX{PE6wN~gd7hVf75^^d}1(p3_IDq>Ugg`)T>qjL$ynty+_4{c^aBA
1&{Kcy5=aV*n#Gk5T5WLcF_avGhh6%PrF`aUTp@3S;a;%DCaJFWV<AH4UeX5i+Z>xkrjAB6W(bR9Va}x
PypN8@2plfX5I`gcq9J)4A9}&rXUUa8&-zcAmON#Cb5R*XXt|+l4S
"""

NONCE = b't\xaa#\x99C\xe5\xd2wS=\xd3\xf9'


def main():
    passwordInput = js.document.getElementById('passwordInput');
    outputArea = js.document.getElementById('outputArea');

    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'@\xc0\xe4\xac\x8a\x83\x9d\xa08S\xe5Uy\x96V\x86',
        iterations=1000000,
    ).derive(passwordInput.value.encode())

    chacha = ChaCha20Poly1305(key)
    try:
        pt = chacha.decrypt(NONCE, base64.b85decode(DATA.replace('\n', '')), None)
    except InvalidTag:
        outputArea.style.color = 'orange'
        return 'Incorrect password? Please try again.<br>(Hint: First 12 characters from my disk encryption password)'

    secrets = json.loads(pt)
    outputs = []
    for k, v in secrets.items():
        secret = base64.b32decode(v)
        totp = TOTP(secret, 6, SHA1(), 30, enforce_key_length=False)
        totp_value = totp.generate(time.time()).decode()
        outputs.append(f'{k}: {totp_value}')

    return '<br>'.join(outputs)

main()
