from jwcrypto import jwk, jwt
from cwt import COSEKey
import json

example = {
    "kty": "EC",
    "d": "xzUEdsyLosZF0acZGRAjTKImb0lQvAvssDK5XIZELd0",
    "use": "sig",
    "crv": "P-256",
    "x": "I3HWm_0Ds1dPMI-IWmf4mBmH-YaeAVbPVu7vB27CxXo",
    "y": "6N_d5Elj9bs1htgV3okJKIdbHEpkgTmAluYKJemzn1M",
    "kid": "12",
}
EXAMPLE_KEY = jwk.JWK(**example)
EXAMPLE_KEY_CWK = COSEKey.from_jwk(example)


def formatToken(input: str, key: jwk.JWK) -> str:
    token = jwt.JWT(jwt=input, key=key, expected_type="JWS", check_claims=False)
    header = printJson(token.header)
    claims = printJson(token.claims)
    return f"""{header}
.
{claims}"""


def printJson(input: str) -> str:
    return json.dumps(json.loads(input), sort_keys=True, indent=2)
