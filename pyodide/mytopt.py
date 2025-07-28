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
s_|QbNxP$ZfN)Cz5=)ju=swC0tmcTAp=b6-qKh#?JfkJNtn^e`esy$-tYsrriubq|ucCZ<yA32R?u?s(
bM$8(c$}t?hLbQcG+P!jb;$pqHYb4#+kGo}W);=r4pQgN(ZptXhtT@6!w_Ea$l{5fZ|`{Yra4HBjI|K(
wS$9yEkJp$&gl|@3|l;#LIkyhNk~K^ME$TfVY*{k(_zKTwCG$}@zVE^rQpNmdHuEdlfS(s4slopT`frn
QWeNBE-OWkn&e8b9x7&k<KK;25bI|YUOjL3^TA5rL15<fnKp!#*wC(ys^s#Ir37~$V~SBOPwK|`iK8vv
CeSJqMry37-~s;L<i%{I3<VqVswQ6xxm#Af;_kEjXFNuwu<zcxX1tUdfWd~&dx?{WN|#B)h*pwgIlY-F
wNA5clI*za=)_$gw`@KUA}-<{0y|W8B4u2k5ze^pGR^YjOHZqH*JgLIj4*S>K3!liQt>56>BHnzzEzU!
bvUSTA587Bovl6*dk=yIZZpXdA~uw1mOFk9bkpx4wJfLp=zS~;fjWE_{zAIJltzk==2Wk^(fTl?curJ6
sCydgU?vjsR<K?J6otgPIXX9}x1P4LkL))>#s7Y8`mH4G%dIWNjPhEgRi>j@whJuf2k_!U`AHO})c4do
YybBspiaFH=Iy5VmG)iWm@yQeo0;WVBCSU1$oTPHidP9BliZlI5(*B#e=PUJPFpdzZxl|yV8cUvy^f3%
rREF6yU)_YZ40gF&4@KE9lH9!T+~&2sgrAR(VI(ZYDc2&O^Pm;#UW~9niAKUl{1hcc?7JntFUe>+$iP)
J821=mc+P+h~Yh~j3)MtJZh2O@xYC~w*xF5<;jw*M86and!T8|i7bGJ4YyB~w_QTMf{rOx!|xY|_LtL5
A|Pu?VqSNL3-nU$c4JdgYX$$Uc6vHt?WSOX);8YCeA=*&X~;VN<1dXg72N
"""

NONCE = b'\x9d\x85\xc7\xfd?\x87?+\xd6p\xd6\xbe'


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
