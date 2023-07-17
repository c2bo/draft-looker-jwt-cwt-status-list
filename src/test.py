from status_list import StatusList
from status_token import StatusListToken
from datetime import datetime, timedelta
import util

# demo key, constant timestamp
key = util.EXAMPLE_KEY
key_cwk = util.EXAMPLE_KEY_CWK
iat = datetime.utcfromtimestamp(1686920170)
gzip_time = iat.timestamp()


test = StatusList(16, 1)
test.set(0, 1)
test.set(1, 0)
test.set(2, 0)
test.set(3, 1)
test.set(4, 1)
test.set(5, 1)
test.set(6, 0)
test.set(7, 1)
test.set(8, 1)
test.set(9, 1)
test.set(10, 0)
test.set(11, 0)
test.set(12, 0)
test.set(13, 1)
test.set(14, 0)
test.set(15, 1)
print(test)
print(bin(test.list[0]), bin(test.list[1]))
print(hex(test.list[0]), hex(test.list[1]))
encoded = test.encode(mtime=gzip_time)
print(encoded)


test = StatusList(12, 2)
test.set(0, 1)
test.set(1, 2)
test.set(2, 0)
test.set(3, 3)
test.set(4, 0)
test.set(5, 1)
test.set(6, 0)
test.set(7, 1)
test.set(8, 1)
test.set(9, 2)
test.set(10, 3)
test.set(11, 3)
print(test)
print(hex(test.list[0]), hex(test.list[1]), hex(test.list[2]))
encoded = test.encode(mtime=gzip_time)
print(encoded)

token = StatusListToken(
    issuer="https://example.com",
    subject="https://example.com/statuslists/1",
    list=test,
    key=key,
    bits=2,
)
exp = iat + timedelta(7)
status_jwt = token.buildJWT(
    exp=exp,
    iat=iat,
    optional_claims={"custom": "value"},
    optional_header={"x5c": ["here_be_dragons"]},
    mtime=gzip_time,
)
print("-----------")
print(status_jwt)
print("-----------")
print(util.formatToken(status_jwt, key))
print("-----------")

status_jwt = token.buildJWT(iat=iat, exp=exp, mtime=gzip_time)
print(status_jwt)
print("-----------")
print(util.formatToken(status_jwt, key))
decoded_list = StatusListToken.fromJWT(status_jwt, key, check_claims=False)
print(decoded_list.list)


# CWT
token._key = key_cwk
status_cwt = token.buildCWT(
    exp=exp,
    iat=iat,
    mtime=gzip_time,
)
print(status_cwt.hex())
token2 = StatusListToken.fromCWT(status_cwt, key_cwk)
print(token.list.list)
print(token2.list.list)
