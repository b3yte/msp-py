import sys
import hashlib
import binascii
import random
import base64
from datetime import date, datetime
from secrets import token_hex
from pyamf import remoting, ASObject, AMF3, amf3


_IS_MACOS = sys.platform == "darwin"
_IS_WINDOWS = sys.platform.startswith("win")

if _IS_MACOS:
    from curl_cffi import requests
elif _IS_WINDOWS:
    import msp_tls_client
else:
    from curl_cffi import requests

def _marking_id():
    _int = random.randint(1, 100)
    while True:
        _int += random.randint(1, 2)
        yield _int

marking_id = _marking_id()


def ticket_header(ticket: str) -> ASObject:

    loc1bytes = str(next(marking_id)).encode('utf-8')
    loc5 = hashlib.md5(loc1bytes).hexdigest()
    loc6 = binascii.hexlify(loc1bytes).decode()
    return ASObject({"Ticket": ticket + loc5 + loc6, "anyAttribute": None})


def calculate_checksum(arguments):
    no_ticket_value = "XSV7%!5!AX2L8@vn"
    salt = "2zKzokBI4^26#oiP"

    def from_array(arguments):
        o = ""
        for i in arguments:
            o += from_object_inner(i)
        return o

    def from_object_inner(Obj):
        if Obj == None:
            return ""
        if type(Obj) == int or type(Obj) == str:
            return str(Obj)
        if type(Obj) == bool:
            return str(Obj)
        if type(Obj) == bytes:
            return from_byte_array(Obj)
        if type(Obj) == list:
            return from_array(Obj)
        if type(Obj) == dict:
            return from_object(Obj)
        if type(Obj) == date:
            return str(Obj.year) + str(Obj.month - 1) + str(Obj.day)
        if type(Obj) == amf3.ByteArray:
            return from_byte_array(Obj)
        if type(Obj) == ASObject:
            return from_object(Obj)

        return ""

    def from_byte_array(bytes):
        if len(bytes) <= 20:
            return bytes.getvalue().hex()

        num = len(bytes) // 20
        array = bytearray(20)
        for i in range(20):
            bytes.seek(num * i)
            array[i] = bytes.read(1)[0]

        return array.hex()

    def get_ticket_value(arr):
        for obj in arr:
            if isinstance(obj, ASObject) and "Ticket" in obj:
                ticket_str = obj["Ticket"]
                if ',' in ticket_str:
                    ticket_parts = ticket_str.split(',')
                    return ticket_parts[0] + ticket_parts[5][-5:]
        return no_ticket_value

    def from_object(obj):
        if "Ticket" in obj:
            return ""

        o = ""
        names = [name for name in obj]
        names.sort()

        for value in names:
            o += from_object_inner(obj.get(value))

        return o

    return hashlib.sha1(f"{from_array(arguments)}{salt}{get_ticket_value(arguments)}".encode()).hexdigest()

def invoke_method(server: str, method: str, params: list,) -> tuple[int, any]:

    server = server.lower()
    if server == "uk":
        server = "gb"
    endpoint = f"https://ws-{server}.mspapis.com/Gateway.aspx?method={method}"

    req = remoting.Request(target=method, body=params)
    event = remoting.Envelope(AMF3)
    event.headers = remoting.HeaderCollection({
        ("sessionID", False, base64.b64encode(token_hex(23).encode()).decode()),
        ("needClassName", False, False),
        ("id", False, calculate_checksum(params))
    })
    event['/1'] = req
    encoded_req = remoting.encode(event).getvalue()

    if _IS_MACOS:
        resp = requests.post(
            endpoint,
            impersonate="chrome",
            headers={
                "Content-Type": "application/x-amf",
                "x-flash-version": "32,0,0,170",
                "Accept-Language": "en-us",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) AdobeAIR/32.0",
                "Connection": "keep-alive",
            },
            data=encoded_req,
            ja3="771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"
        )
    else:
        sess = msp_tls_client.Session(client_identifier="xerus_ja3_spoof", force_http1=True)
        resp = sess.post(
            endpoint,
            data=encoded_req,
            headers={
                "Referer": "app:/cache/t1.bin/[[DYNAMIC]]/2",
                "Accept": ("text/xml, application/xml, application/xhtml+xml, "
                           "text/html;q=0.9, text/plain;q=0.8, text/css, image/png, "
                           "image/jpeg, image/gif;q=0.8, application/x-shockwave-flash, "
                           "video/mp4;q=0.9, flv-application/octet-stream;q=0.8, "
                           "video/x-flv;q=0.7, audio/mp4, application/futuresplash, "
                           "/;q=0.5, application/x-mpegURL"),
                "x-flash-version": "32,0,0,100",
                "Content-Type": "application/x-amf",
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "Mozilla/5.0 (Windows; U; en) AppleWebKit/533.19.4 "
                              "(KHTML, like Gecko) AdobeAIR/32.0",
                "Connection": "Keep-Alive",
            }
        )

    if resp.status_code != 200:
        return (resp.status_code, resp.content)
    return (resp.status_code, remoting.decode(resp.content)["/1"].body)
