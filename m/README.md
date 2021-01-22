### Encrypt
```bash
xz -z -c IN | openssl aes256 -e -pbkdf2 -out OUT
```

### Decrypt
```bash
openssl aes256 -d -pbkdf2 -in OUT | xz -d > IN
```
