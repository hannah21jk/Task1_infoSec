import hashlib

hash = hashlib.md5("password".encode("utf-8")).hexdigest()
print(str(hash))