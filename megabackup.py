from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding

from getpass import getpass
from binascii import hexlify, unhexlify
from os import urandom


SALT = 'b18ffb875b3cef26e3acd277f4a4f42c'


def gen_salt():
    return hexlify(urandom(16)).decode()


def get_keyiv():
    # Hint: my disk encryption password
    secret = Scrypt(
        salt=unhexlify(SALT),
        length=48, n=2**18, r=8, p=1
    ).derive(getpass('Password:').encode())
    return secret[:32], secret[32:]


def encrypt():
    plain_text = """

    """.strip()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    
    key, iv = get_keyiv()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    cipher_hex = hexlify(encryptor.update(padded_data) + encryptor.finalize()).decode()
    return '\n'.join([cipher_hex[i:i+80] for i in range(0, len(cipher_hex), 80)])


def decrypt():
    cipher_text = """
ac2b2c939fb47f5231740f8a43fb437f2b173a4e41ea589398500b9f5f2122a1d51b45db3156440f
e95633df032ed15d1969df4772f818295b7de7f494a5d9e62bef0a323c5e76c37c6224e414e43290
47b8c60404d1645cbd07c26fc2c49f624c40078722750e69f4639fbf765910f103ebbb1142ab23a4
5ff2391d8207968ae23ba847bc814fd3190d50227d379ce9a912cf3c65993d11797e9d03fd5ec385
b1eac8c261c7ab229b1ea4132e720aef61ee55808b7eed506929088c5a0a47b9b86cd49a42710e78
e9fc797be56622f3e98808e487b9f5b026425b134035da2ed439b9c257bc6a9aec66e783960bbbd7
436172031579f9a6eb12fa12794197524e6fc0411f142d18750811128ccd210cec208ef085b02cc1
f4dbb31b01e79caadb932ce794905fa0904dc579cdbd255a6d3c0e4d812010c81d6d6d1a03f1cd75
1eb150a6c8fcc7e6ca395b2a743be695efc95d165ebda7bdd74da937d6ec1b29dc5554745c6defe3
a448a028abff17d341f03583775f11494f2d674dd26241e642e1557cb583be0262c4605d48f1b51a
3717daca79eb65648da209e612eea72341460b90b54af54560b8897fe0057bf870b8013be4f5aa0e
379cb8e7d408aa9058fcee1e5f1e08e4eb32983f9aeefae353874124b4077d4fae9b3aa1a61e3ad6
2b932c3ed047f11450d6adff1c1ccb6a39ea7fb48d8a2b147e09b365d359de4c27ffcc66284b50aa
dd0b289a9484f5cdff40baeb704c905c7f5180b1765db2e9ad51b6d063e9686c23ed15c46b43142b
0dcf2b4ce1342884e7eb109dee18d8ead9e052617c94f9f4cfdaf805d48c7cdf480cb7558d1b3f68
f7c9ca0470fff267f6e1bc9363ca18c5a4ba767ba14f189e99c90a86c89bfa8337f8bbb1ecfcabab
1b97b933f4ed3c10ae2992bb62f3dc82b7575b10cc2900904d6455dc928ab3b0f85b477be2b01145
385881c2b6b36a08cb0cd7af3863b846001db573699a83604454601cf04b5ffcb25d29c1d47aae25
aeb2c7a5a9023f1881e2f7021ef2aff51d5c8638dbd03b4a6e875e2064541444426b3a90139c6a6d
dab37fd3e4b086ba6638e4ca8efa9ac8d200f6e05e43721bfd37f946412a64048f06783f440b3e01
a1eca3906bfd6d3eb2ab484a1459280b084554f16b48f6f8c77b3bccfeaca538770661cdff209b55
acb7c4a4495a53be987699c3c121f948648aa7a4db143228f20b4cc60f901caa3523490572575549
0f471d1b99e17048e2b849cd16acd948bea6588b9d56ff6cbe5a1f4bdcfa7a4c4bdd60c893ab1a51
676b1ae95f965819f2f22a0f0069060a1a17537fbb60f53da5ec805bdcc47772996d0f41de158f20
23ffeb66ee9e5c01593ca89ab384c9a6c2100f1415aa407762f77f55a0fbbb53
    """.replace(' ', '').replace('\n', '')

    key, iv = get_keyiv()
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded_data = decryptor.update(unhexlify(cipher_text)) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_data) + unpadder.finalize()).decode()


if __name__ == '__main__':
    # print(encrypt())
    print(decrypt())
    # print(gen_salt())

