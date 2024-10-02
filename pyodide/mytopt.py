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
#G_^D42U8)N>2nEbXH-v)PV&<R*O|f8z85%2;cIzpvz8kB(aL3km09D@PzH9vRF`G9syz1qW@xsG1CjY
55d0H3w@lDoiVBJ!0i*K>5SJ9H*c<+fK|yI2=p*XEywXLiq#zG|2^;XUPl)b0#5IvBLOi7V4>oh1N5(`
tXsA=;y!P=T6D_il!qUT^j+WT*`Y}9sDzhlfj-Ix18}3=K~v%ktT!5n;75gbb068zE9MU6e8ju&7Q8>0
5n;_)()Ivug^jSlvL;1Q_MCu&nT!*yt}&0=gc;RASB$j7gAW0WhQw*%2*+~9Fn#Ag(fPi_-cqq`O-%Fz
gHHI7?>89y+}MF}+A3<LuLf8b!c^z=|3DqVPo~%uE+6DOJ!d%$lsOm)Rk0vJ4yK_VV@e_tHkHT^)~{k^
h-oZ}{UZx0o|7AFcXKnfE6^j`bybu(v4_K=+%EjQ0Aj-8WI;bf^h#Q$%_IS~4xC1KC?}#6pdYXkGPeG1
0!E_w3qdFD>5>ipwbxqJsbxty(_?F!`_8o~pYl2j2o`s0{9C7nzcs7>UwuJYY2)FKs*@8a3Ov6R#Ea+|
C~_2EiH9u|HpBmTQqR1Y|6@s4*VcDO><UmV=@rsc*pYA6UwLGMy-UV}coDj{A$=SunjLnj_p>BVEj<oL
mJ`jkU+LXj%PcM$GWm|#&z#{qs=(GwFqWmxgwBHpmT@%x^kmQ;a1Zor4oBYurM=uTYkZL`AWG<GQ&%19
w&mQ01l})!=pFA^m_>MJkQu%N@YSt1)ww@!>pzreOVD<5`HH6C)?=oFC}^*jFCNvDc5i6pE&ixc8}+1&
eL*F<n)f=}GsNz(MV`2yz+m}{m68jdDidlksqri9gKGZ$s5lDj4prI
"""

NONCE = b'4!\xceq8\x06\xf4\xd0\xc2\xa0\x02\x82'


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
