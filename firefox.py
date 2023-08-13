# Necessary Imports
import os
import sys
import shutil
import ctypes as ct
from base64 import b64decode
from configparser import ConfigParser

# Global Variables
FIREFOX_PATH = os.path.join(os.environ["APPDATA"], "Mozilla", "Firefox")

# Define the SECItem structure
class SECItem(ct.Structure):
    _fields_ = [
        ("type", ct.c_int),
        ("data", ct.c_char_p),
        ("len", ct.c_int),
    ]
    def decode_data(self):
        _bytes = ct.string_at(self.data, self.len)
        return _bytes.decode('utf-8')

def getAllProfiles(profile_path:str) -> list:
    ini = os.path.join(profile_path, "profiles.ini")

    if not os.path.isfile(ini):
        raise Exception(f'profile.ini not found in path {profile_path}.')
    
    profiles = ConfigParser()
    profiles.read(ini, encoding='utf-8')

    sections = {}
    i = 1
    for section in profiles.sections():
        if section.startswith("Profile"):
            sections[str(i)] = profiles.get(section, "Path")
            i += 1
        else:
            continue

    return  [os.path.join(profile_path, section, 'logins.json').replace('\\', '/') for key, section in sections.items()]

def locateAndLoadNss() -> ct.CDLL:

    # Locating nss
    nnsName = 'nss3.dll'
    locations: list[str] = [
                "",  # Current directory or system lib finder
                os.path.expanduser("~\\AppData\\Local\\Mozilla Firefox"),
                os.path.expanduser("~\\AppData\\Local\\Firefox Developer Edition"),
                os.path.expanduser("~\\AppData\\Local\\Mozilla Thunderbird"),
                os.path.expanduser("~\\AppData\\Local\\Nightly"),
                os.path.expanduser("~\\AppData\\Local\\SeaMonkey"),
                os.path.expanduser("~\\AppData\\Local\\Waterfox"),
                "C:\\Program Files\\Mozilla Firefox",
                "C:\\Program Files\\Firefox Developer Edition",
                "C:\\Program Files\\Mozilla Thunderbird",
                "C:\\Program Files\\Nightly",
                "C:\\Program Files\\SeaMonkey",
                "C:\\Program Files\\Waterfox",
            ]

    software = ["firefox", "thunderbird", "waterfox", "seamonkey"]
    for binary in software:
        location = shutil.which(binary)
        if location is not None:
            nsslocation: str = os.path.join(os.path.dirname(location), nnsName)
            locations.append(nsslocation)


    for loc in locations:
        nsslib = os.path.join(loc, nnsName)
        # print(f"Loading NSS library from {nsslib}", )

        os.environ["PATH"] = ";".join([loc, os.environ["PATH"]])

        if loc:
                if not os.path.isdir(loc):
                    # No point in trying to load from paths that don't exist
                    continue

                workdir = os.getcwd()
                os.chdir(loc)

        try:
            nss: ct.CDLL = ct.CDLL(nsslib)
        except OSError as e:
            print(e)
        else:
            print("Loaded NSS library from ", nsslib)
            return nss

def decrypt(profile:str, data, nss):
    # Define the PK11_ReadRawAttribute function prototype
    PK11_ReadRawAttribute = nss.PK11_ReadRawAttribute
    PK11_ReadRawAttribute.argtypes = [ct.c_char_p, ct.c_char_p, ct.POINTER(SECItem)]
    PK11_ReadRawAttribute.restype = ct.c_int


    # Define the decryption function prototype
    PK11SDR_Decrypt = nss.PK11SDR_Decrypt
    PK11SDR_Decrypt.argtypes = [ct.POINTER(SECItem), ct.POINTER(SECItem), ct.c_void_p]
    PK11SDR_Decrypt.restype = ct.c_int

    profile_path = b"sql:" + bytes(profile.strip('logins.json') , 'utf-8')

    init_status = nss.NSS_Init(profile_path)
    if init_status != 0:
        print("NSS Library initialization failed!")
        sys.exit()

    # Perform decryption
    data = b64decode(data)

    inp = SECItem(0, data, len(data))
    out = SECItem(0, None, 0)
    status = PK11SDR_Decrypt(inp, out, None)

    if status == 0:
        return out.decode_data()
        # Handle the decrypted data in 'out' if needed
    else:
        return 'Can not be decrypted.'
        # Handle the decryption failure

    

