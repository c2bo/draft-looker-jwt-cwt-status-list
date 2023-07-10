from jwcrypto import jwk, jwt
from cwt import COSEKey, COSE, COSEHeaders, CWTClaims
from status_list import StatusList
from datetime import datetime
from typing import Dict, Union, List
import json

DEFAULT_ALG = "ES256"
STATUS_LIST_TYP_JWT = "statuslist+jwt"
STATUS_LIST_TYP_CWT = "statuslist+cwt"
# TODO: change to this value
STATUS_LIST_CWT_ID = -70001


class StatusListToken:
    list: StatusList
    issuer: str
    subject: str
    _key: Union[jwk.JWK, Union[COSEKey, List[COSEKey]]]
    _alg: str

    def __init__(
        self,
        issuer: str,
        subject: str,
        key: Union[jwk.JWK, Union[COSEKey, List[COSEKey]]],
        list: StatusList = None,
        size: int = 2**20,
        bits: int = 1,
        alg: str = None,
    ):
        if list is not None:
            self.list = list
        else:
            self.list = StatusList(size, bits)
        self.issuer = issuer
        self.subject = subject
        self._key = key
        if alg is not None:
            self._alg = alg
        else:
            self._alg = DEFAULT_ALG

    @classmethod
    def fromJWT(cls, input: str, key: jwk.JWK, check_claims=None):
        decoded = jwt.JWT(
            jwt=input, key=key, expected_type="JWS", check_claims=check_claims
        )
        header = json.loads(decoded.header)
        alg = header["alg"]
        typ = header["typ"]
        assert typ == STATUS_LIST_TYP_JWT
        claims = json.loads(decoded.claims)
        status_list = claims["status_list"]
        lst = status_list["lst"]
        bits = status_list["bits"]
        issuer = claims["iss"]
        subject = claims["sub"]
        list = StatusList.fromEncoded(encoded=lst, bits=bits)

        return cls(
            issuer=issuer,
            subject=subject,
            key=key,
            list=list,
            size=list.size,
            bits=list.bits,
            alg=alg,
        )

    @classmethod
    def fromCWT(
        cls, input: bytes, keys: Union[COSEKey, List[COSEKey]], check_claims=True
    ):
        cose = COSE.new()
        p, u, claims = cose.decode_with_headers(data=input, keys=keys)
        alg = p[COSEHeaders.ALG]
        typ = p[COSEHeaders.CTY]
        assert typ == STATUS_LIST_TYP_CWT
        status_list = claims[STATUS_LIST_CWT_ID]
        lst = status_list["lst"]
        bits = status_list["bits"]
        issuer = claims[CWTClaims.ISS]
        subject = claims[CWTClaims.SUB]
        list = StatusList.fromEncoded(encoded=lst, bits=bits)

        return cls(
            issuer=issuer,
            subject=subject,
            key=keys,
            list=list,
            size=list.size,
            bits=list.bits,
            alg=alg,
        )

    def set(self, pos: int, value: int):
        self.list.set(pos, value)

    def get(self, pos: int) -> int:
        return self.list.get(pos)

    def buildJWT(
        self,
        iat: datetime = datetime.utcnow(),
        exp: datetime = None,
        optional_claims: Dict = None,
        optional_header: Dict = None,
        compact=True,
        mtime=None,
    ) -> str:
        # build claims
        if optional_claims is not None:
            claims = optional_claims
        else:
            claims = {}
        claims["sub"] = self.subject
        claims["iss"] = self.issuer
        claims["iat"] = int(iat.timestamp())
        if exp is not None:
            claims["exp"] = int(exp.timestamp())
        encoded_list = self.list.encode(mtime=mtime)
        claims["status_list"] = {
            "bits": self.list.bits,
            "lst": encoded_list,
        }

        # build header
        if optional_header is not None:
            header = optional_header
        else:
            header = {}
        if self._key.key_id:
            header["kid"] = self._key.key_id
        header["alg"] = self._alg
        header["typ"] = STATUS_LIST_TYP_JWT

        token = jwt.JWT(header=header, claims=claims)
        token.make_signed_token(self._key)
        return token.serialize(compact=compact)

    def buildCWT(
        self,
        iat: datetime = datetime.utcnow(),
        exp: datetime = None,
        optional_claims: Dict = None,
        optional_header: Dict = None,
        mtime=None,
    ) -> str:
        # build claims
        if optional_claims is not None:
            claims = optional_claims
        else:
            claims = {}
        claims[CWTClaims.SUB] = self.subject
        claims[CWTClaims.ISS] = self.issuer
        claims[CWTClaims.IAT] = int(iat.timestamp())
        if exp is not None:
            claims[CWTClaims.EXP] = int(exp.timestamp())
        encoded_list = self.list.encode(mtime=mtime)
        claims[STATUS_LIST_CWT_ID] = {
            "bits": self.list.bits,
            "lst": encoded_list,
        }

        # build header
        if optional_header is not None:
            header = optional_header
        else:
            header = {}
        header[COSEHeaders.CTY] = STATUS_LIST_TYP_CWT

        cose = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
        token = cose.encode_and_sign(payload=claims, key=self._key, protected=header)
        return token
