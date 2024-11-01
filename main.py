
import time
import base64
from   re                                        import findall, sub
from   pytermx                                   import Color
from   datetime                                  import datetime
from   tls_client                                import Session
from   cryptography.hazmat.backends              import default_backend
from   cryptography.hazmat.primitives            import serialization, hashes
from   cryptography.hazmat.primitives.asymmetric import ec

class Print:
    @staticmethod
    def _message(typee, text):
        try:
            text = sub(r'\[(.*?)]', rf"{Color.GREY}[{Color.BRIGHT_WHITE}\1{Color.GREY}]{Color.BRIGHT_WHITE}", text)
        except:
            pass

        return f"{Color.BLACK}{datetime.now().strftime('%H:%M:%S')} {typee} {Color.BRIGHT_WHITE} {text}"

    @staticmethod
    def inf(text: str):
        print(Print._message(f"{Color.BLUE}INF", text))
    
    @staticmethod
    def vert(text: str, **kwargs):
        first_message = Print._message(f"{Color.GREEN}INF", f"{Color.BLUE}{text}{Color.BRIGHT_WHITE}")

        for index, (key, value) in enumerate(kwargs.items()):
            prefix = "\t ├" if index < len(kwargs) - 1 else "\t └"
            line = f"{prefix} {Color.BRIGHT_WHITE}{key}: {value}"

            first_message += f"\n{line}"

        print(first_message)

class Roblox:
    def __init__(self) -> None:
        self.session = Session(
            client_identifier = "firefox_121",
            random_tls_extension_order = True
        )
        self.session.headers = {
            "accept": "*/*",
            "accept-language": "en-GB,en;q=0.9",
            "cache-control": "no-cache",
            "origin": "https://www.roblox.com",
            "pragma": "no-cache",
            "priority": "u=1, i",
            "referer": "https://www.roblox.com/",
            "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        }

    def gen_signature(self):
        self.session.headers["authority"] = "www.roblox.com"

        res = self.session.get(
            url = "https://www.roblox.com/"
        ).text

        csrf = findall(r'<meta name="csrf-token" data-token="(.*?)" />', res)[0]
        self.session.headers["x-csrf-token"] = csrf

        serverNonce = self.session.get(
            "https://apis.roblox.com/hba-service/v1/getServerNonce"
        ).text.split('"')[1]

        Print.inf(f"Get Server Nonce. [{serverNonce[:50]}...]")
        
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend()
        )

        public_key = private_key.public_key()

        public_key_spki = base64.b64encode(public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        Print.inf(f"Get Client Public Key. [{public_key_spki[:50].decode('utf-8')}...]")

        data = f"{public_key_spki}:{int(time.time())}:{serverNonce}".encode("utf-8")

        signature = base64.b64encode(private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        ))

        Print.inf(f"Get saiSignature. [{signature[:50].decode('utf-8')}...]")

Roblox().gen_signature()