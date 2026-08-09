#!/usr/bin/env python3
import asyncio
import csv
import gzip
import hashlib
import html
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import time
import unicodedata
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import BoundedSemaphore, Condition, Lock, RLock, Thread
from urllib import request as urlrequest
from urllib.parse import parse_qs, urlparse

def _clean_domain_value(value):
    return str(value or "").lower().strip().rstrip(".").lstrip("@")


def _env_domains(value):
    return [
        domain
        for domain in (_clean_domain_value(item) for item in str(value or "").split(","))
        if domain
    ]


DOMAIN = _clean_domain_value(os.environ.get("MAIL_DOMAIN", "example.com"))
ROOT_DOMAINS = tuple(dict.fromkeys(
    domain
    for domain in ([DOMAIN] + _env_domains(os.environ.get("MAIL_ROOT_DOMAINS", DOMAIN)))
    if domain
))
EXTRA_DOMAINS = os.environ.get("MAIL_EXTRA_DOMAINS", "")
BOOTSTRAP_DOMAINS = tuple(dict.fromkeys(
    domain
    for domain in list(ROOT_DOMAINS) + _env_domains(EXTRA_DOMAINS)
    if domain
))
PANEL_TOKEN = os.environ.get("PANEL_TOKEN", "")
DB_PATH = os.environ.get("DB_PATH", "/var/lib/ferret-mail/inbox.sqlite3")
SMTP_HOST = os.environ.get("SMTP_HOST", "0.0.0.0")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
HTTP_HOST = os.environ.get("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8710"))
PUBLIC_IP = os.environ.get("PUBLIC_IP", "127.0.0.1")
RETENTION_HOURS = int(os.environ.get("RETENTION_HOURS", "72"))
MAX_MESSAGE_BYTES = int(os.environ.get("MAX_MESSAGE_BYTES", str(25 * 1024 * 1024)))
MAX_TEXT_CHARS = int(os.environ.get("MAX_TEXT_CHARS", "180000"))
MAX_ATTACHMENT_BYTES = int(os.environ.get("MAX_ATTACHMENT_BYTES", str(10 * 1024 * 1024)))
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/var/lib/ferret-mail/backups")
MAX_BACKUP_BYTES = int(os.environ.get("MAX_BACKUP_BYTES", str(1024 * 1024 * 1024)))
MAX_BACKUPS = int(os.environ.get("MAX_BACKUPS", "30"))
AUTO_BACKUP_HOURS = int(os.environ.get("AUTO_BACKUP_HOURS", "24"))
DEFAULT_ALIAS_LIMIT = int(os.environ.get("DEFAULT_ALIAS_LIMIT", "500000"))
DEFAULT_MAIL_LIMIT = int(os.environ.get("DEFAULT_MAIL_LIMIT", "50000"))
DEFAULT_STORAGE_LIMIT_MB = int(os.environ.get("DEFAULT_STORAGE_LIMIT_MB", "1024"))
API_MAX_BODY_BYTES = int(os.environ.get("API_MAX_BODY_BYTES", str(2 * 1024 * 1024)))
AUTH_FAIL_LIMIT = int(os.environ.get("AUTH_FAIL_LIMIT", "20"))
API_RATE_LIMIT_PER_MIN = int(os.environ.get("API_RATE_LIMIT_PER_MIN", "240"))
API_MUTATION_RATE_LIMIT_PER_MIN = int(os.environ.get("API_MUTATION_RATE_LIMIT_PER_MIN", "90"))
LONG_POLL_RATE_LIMIT_PER_MIN = int(os.environ.get("LONG_POLL_RATE_LIMIT_PER_MIN", "30"))
LONG_POLL_MAX_ACTIVE_PER_IP = int(os.environ.get("LONG_POLL_MAX_ACTIVE_PER_IP", "6"))
ALIAS_SHARE_RATE_LIMIT_PER_MIN = int(os.environ.get("ALIAS_SHARE_RATE_LIMIT_PER_MIN", "120"))
ALIAS_SHARE_TOKEN_RATE_LIMIT_PER_MIN = int(os.environ.get("ALIAS_SHARE_TOKEN_RATE_LIMIT_PER_MIN", "240"))
SMTP_CONN_RATE_LIMIT_PER_MIN = int(os.environ.get("SMTP_CONN_RATE_LIMIT_PER_MIN", "60"))
SMTP_MAX_RCPTS_PER_MESSAGE = int(os.environ.get("SMTP_MAX_RCPTS_PER_MESSAGE", "25"))
SMTP_COMMAND_LIMIT = int(os.environ.get("SMTP_COMMAND_LIMIT", "250"))
SMTP_MAX_CONNECTIONS = int(os.environ.get("SMTP_MAX_CONNECTIONS", "32"))
SMTP_IDLE_TIMEOUT_SECONDS = int(os.environ.get("SMTP_IDLE_TIMEOUT_SECONDS", "120"))
SMTP_DATA_TIMEOUT_SECONDS = int(os.environ.get("SMTP_DATA_TIMEOUT_SECONDS", "120"))
HTTP_MAX_CONNECTIONS = int(os.environ.get("HTTP_MAX_CONNECTIONS", "128"))
HTTP_REQUEST_TIMEOUT_SECONDS = int(os.environ.get("HTTP_REQUEST_TIMEOUT_SECONDS", "30"))
MIN_DISK_FREE_BYTES = int(os.environ.get("MIN_DISK_FREE_BYTES", str(512 * 1024 * 1024)))
BACKUP_MAX_AGE_HOURS = int(os.environ.get("BACKUP_MAX_AGE_HOURS", str(max(48, AUTO_BACKUP_HOURS * 2))))
SQLITE_SYNCHRONOUS = os.environ.get("SQLITE_SYNCHRONOUS", "FULL").strip().upper()
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
if SQLITE_SYNCHRONOUS not in {"FULL", "EXTRA", "NORMAL"}:
    raise ValueError("SQLITE_SYNCHRONOUS must be FULL, EXTRA, or NORMAL")
LOG_RETENTION_DAYS = int(os.environ.get("LOG_RETENTION_DAYS", "180"))
FAILED_MAIL_RETENTION_DAYS = int(os.environ.get("FAILED_MAIL_RETENTION_DAYS", "90"))
MAX_OPERATION_LOGS = int(os.environ.get("MAX_OPERATION_LOGS", "50000"))
MAIL_METADATA_VERSION = 1
CORS_ALLOWED_ORIGINS = {
    o.strip().rstrip("/")
    for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
    if o.strip()
}
_DEFAULT_TRUSTED_HOSTS = [PUBLIC_IP, "127.0.0.1", "localhost"]
for _root_domain in ROOT_DOMAINS:
    _DEFAULT_TRUSTED_HOSTS.extend([_root_domain, f"mail.{_root_domain}", f"*.{_root_domain}"])

TRUSTED_HOSTS = {
    h.lower().strip()
    for h in os.environ.get(
        "TRUSTED_HOSTS",
        ",".join(dict.fromkeys(_DEFAULT_TRUSTED_HOSTS)),
    ).split(",")
    if h.strip()
}
FAVICON_SVG = b'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
<defs>
<linearGradient id="bg" x1="20" y1="8" x2="108" y2="120" gradientUnits="userSpaceOnUse">
<stop offset="0" stop-color="#4aa3df"/><stop offset=".55" stop-color="#1769aa"/><stop offset="1" stop-color="#083f76"/>
</linearGradient>
<linearGradient id="paper" x1="64" y1="39" x2="64" y2="92" gradientUnits="userSpaceOnUse">
<stop offset="0" stop-color="#fffaf0"/><stop offset=".55" stop-color="#f7ecd2"/><stop offset="1" stop-color="#dfc99d"/>
</linearGradient>
<filter id="shadow" x="-20%" y="-20%" width="140%" height="150%">
<feDropShadow dx="0" dy="8" stdDeviation="5" flood-color="#07182a" flood-opacity=".35"/>
</filter>
<filter id="soft" x="-20%" y="-20%" width="140%" height="140%">
<feDropShadow dx="0" dy="4" stdDeviation="2" flood-color="#5b3d1b" flood-opacity=".28"/>
</filter>
</defs>
<rect x="10" y="8" width="108" height="108" rx="26" fill="url(#bg)" filter="url(#shadow)"/>
<path d="M19 18h90v44c-20 12-59 9-88-1C16 48 15 30 19 18z" fill="#fff" opacity=".18"/>
<path d="M36 25c25-8 50-2 69 13" fill="none" stroke="#fff" stroke-opacity=".28" stroke-width="3" stroke-linecap="round"/>
<g filter="url(#soft)">
<rect x="24" y="39" width="80" height="52" rx="9" fill="url(#paper)" stroke="#b99f68" stroke-width="2"/>
<path d="M27 88l29-25 8 7 8-7 29 25z" fill="#ead6aa" stroke="#a9854e" stroke-width="2" stroke-linejoin="round"/>
<path d="M28 42l36 28 36-28z" fill="#fffdf5" stroke="#b99f68" stroke-width="2" stroke-linejoin="round"/>
<path d="M35 44l29 22 29-22" fill="none" stroke="#fff" stroke-opacity=".72" stroke-width="2" stroke-linecap="round"/>
<circle cx="86" cy="69" r="8" fill="#bd392f" stroke="#842421" stroke-width="1.5"/>
<circle cx="86" cy="69" r="4" fill="#e86d59" opacity=".74"/>
</g>
<circle cx="41" cy="27" r="8" fill="#fff" opacity=".24"/>
<rect x="10" y="8" width="108" height="108" rx="26" fill="none" stroke="#06375f" stroke-opacity=".45" stroke-width="2"/>
</svg>'''
FAVICON_PNG_HEX_UNUSED = (
    "89504e470d0a1a0a0000000d4948445200000080000000800806000000c33e61cb"
    "000021154944415478daed5d7bb05e55755f6b7f17c80c6389ad759a08ea2d0e"
    "185e5646472842461ed5110c58b52dc5d1aaed54adb6500952cb9561221d2c885"
    "63aa2b66ac504048a4120bcf28084aae8b416ad21028148c050edb423e1666eeee"
    "3dbab7fecd75a6bef73bef3bd6e726fee61c2fdeefdce39dff9f66faddf7aecb5d"
    "7065838168e8563e158380ed0038773afec25eaf330fc285f83b3fcec833aa8c11"
    "954713ab1b7a8ea0aa8f9655f0940431011311309c4fc3e587d7f9c43aa457582"
    "51029ae30f44fc4703e1d9570280f5c023ca77e2afe21c2916587df3392c000579"
    "e00a4fd99544944e54e7940581665300b020030c5c94e025e5470935fb5d58067e"
    "739c072680e47b14fecf25403200230152acc0ef40fdb201f6adf5658df7d84202"
    "1e01a5194094fe0166a6019b3d23ee5b59a026834e5436f52475da693da5f3489"
    "e4365f3900b020d4b00b083d62b9a0f202362fa3d026e8e39ef92053fdc1df6"
    "d1dbff9e293979d5a72430c92400c5f7ead8800629005a1999de7b7091533ca2"
    "a0782714688e79fbc717a06e2a106b3fedb59ea4890882e07e27612e38f0cd04a"
    "1cb704b987764a65c53bd618a8fe698f38ac02f7fffe563e9f9b0e03a53f17b10"
    "e591120080b55474eadf6b1bc7e49b75b8e239115b722b2ca62a76bad3837bd47"
    "0040d6b2cfb0c268c4cf00806debbeb6aa82193e1d3ed0dfd50ad310d940b809"
    "d4d42fc0ae349f818fd2b3c700b6170853a2f8e51fb87c2c0314b1604649b9cd"
    "0a286d83490a7f3c47f95562a81850dcdf12f7b124d44a088957c404663ad746"
    "25153e9c1708ca9e9380fcdfd3b33e76cf0dab8a2682c826d3101e42f90e5d98"
    "846e0480db73e1d825ad4704cc355e02ef9e0511810a015200df7d0a299cb590"
    "7041c9436a3ef8e16dcbb40e988652414800387b4890480b14d36eaef5823d94"
    "d6936212ce3a41889eb86ff5aa8c11287c73c606c4c58d4b72ef028025da47e1"
    "e1a3018fba7fcb70ad3fedfd978f491cebb53efd7db05abff9e2134fe9d5169f"
    "74e577bf237df8643ab83647cda72c8c17a689144b0b868802ad04c35ad8befe"
    "c6558a0d6c140477331bb447f905b542805d6a7ea27c0f3a02184044403466d97"
    "92b13f89f1c93413d079f548ed0fd69c35f1d333a00ff69e92cf868bbfabdc10"
    "99fb86f87d0fa28288a1128999f27b9106cbbfd6a472d440460997d2216257464"
    "02ec0f7c348088886870d9b92b83d687cfe3344ef16624b206ebff72d96c80be"
    "6b3fbd3700001c7fe93d3b08b2bc4f913980009edc70d32a0000daf6edab290a"
    "01f524045893584191b373b6de78e03dfdbb7f66d9b91747f0fd83d6813f644d"
    "df350b0c30b4cf3ef6e377ede05aaf1dd2f0f71d1b6f5ee598e0dbd77826b0e"
    "e2cef581058ef27709790b4edc50e761fd90fe7e879baf7af0d46f03f3996581"
    "e8587cc27040600fed27d04faac3dcf3197dcb5436bbd745e9d43ba63d32d810"
    "9ae212f004064bdf2dbe4184621c858009b53bf031e3b802f3dfc04fe1080df97"
    "a0cfca332e5b79c70eeed4920a2f09087eb6e9d64c082831424753600a04500d"
    "3eb8f81e113180af434d446419ed8150fe5235b0bbf653f04bcfb6b41fa774db"
    "d52b46a910fd88303f20b7ecdc8b31e662bc794e8eba9a7b497a6f3253c053ba"
    "31c903181d010c37f7defefb3ee9b379c13e258940c47ec09f4bc00f4d107e7"
    "acdb9a331aa233ed26e985ff9a6778e31afda3134c30b32e73d0bc04a8e9fcce"
    "8054f1f105b88c6e0ab577c0c00e0d43f191b0b77a08243b1f1c263470740a"
    "57305f4a17e9f577fecf61ddc0fe039084b043b1fbccd99829fdef119226b81a"
    "81d22842c83c8f20386e156a27e885a9f327d4665ebc52466f87b8fe0734dd90"
    "5002f068063d5bfb9787046e8890d7efa99f346e564881f7b1ddaa3c709121b7"
    "8e54fa640d87ba9fda590cf001a83882d4063f0d56ffb6ba7fd978de9a44ef0f"
    "e375e78dc689f5af2e206e76f3d10d9e0a88b6edba1e71b8283b873f3b73c0"
    "bdc792d90b544d406b236e608f2d0903981289c402f29e8b37c10133e520825f"
    "8944de2743d282f6e083ecc6146d8d54fd63268bd4eb1934cb009dc00822917"
    "0a0fe0de00c6047c0e3f9c9928058e3ee742008037bef7b231284ccc00016cb"
    "aa86bed5f3a8f6c7daf26a1f1f1c467df31aa937ae1e511a79de71cc2a3cfb"
    "990e3c61d425426c0700b20fd003fc1e32c824165fb85ecf95ffb04bf576d3e"
    "768e0b420f42f0ced1a0f5e5bad2c80226c66e3caf0749bdb913986af563281"
    "8d3be280b7ca5d66ba158d0fce10b8118f692dd45851f039f418926fe91d97e"
    "0cf642683fb3ffa0e7e117c0df174220ca04b3e4508802020b00130688219e91"
    "690051e429a5e7a8b77e0400e094f77c62aca4f59b2e3a7eb44ff07bf5eab7"
    "1e8842b0fd73ef1a55c13800011c7eeab9ce0f38eaad1fc9583c0bf9bd09e02"
    "4e0cfc7683b50c7fe4aeba954b0b1a0f9b3210404acde830a6c8c71f22ee21"
    "9f33b293c909a8f29371024c6a0b0ffe5ea980181bfb50b8dde3a8fb4bf4721"
    "c87d30926e0042f4f338f527bfcfe4f42fa2c0e0fc99ec7399d63ff8b1d78c36"
    "041f0600ee7c05beeb717beaf37f342ae661f268c088625d99064040c411cc25"
    "86d3bfd111405549760f499003c9bef7c2028d95a65c5c1bb2730e4702b40084"
    "400ed030b5c4e8412cea5289a1b20980acfc7cc1eecfb629c8c1574680257e"
    "90afccc29808127e617410805502659388b12cbd23fe4b17701cb229a0ea56023"
    "198175180e8cb10f300a5960efa62a1f5d45d0e6041fbfb63814686803238108"
    "1e77444cad7413c02c22b444cbc2fa40673812b550034a7febd7bf7e202bef25"
    "8b46811d5f8034bcb63492a19a83820c5f64048def887bf138d14a20094d961"
    "bea2370f039ba25805f8e4e4e4012f08871c720895c6a84220320b4054c1c4"
    "c1809332efde0504041c5117f057dcf4a300ddd7011080eaf2926bbffe5201f0"
    "efdf75cd930b3a2f8f379c73f191258158b468514716088795cbd2e2e40e659"
    "6de1d23f1efc86b01c2dfd294a0163b6a100672f01780ef7c84b12909c2a24"
    "58beae280a89c9a000010c9f1bf5b77e7a401fd4f1aa9b8aba27dc90049eb2"
    "b0b40a2e607e0272727f191f5d76dc799f105a41b08c2ef9cf5d1577113b1"
    "77efdee7aa4c424d2a5e723a95190041a48884cf879928443350adfc1cfc200"
    "08facbf6e3b00c059e7af84f5375d0d67bdfbf205a4d5b17ef51570d6f92b"
    "e1fe5baf871faffbd443279c7dd9a94a08500b0165bd0f48c21f343e2ece1"
    "299603dc9532940ca09acae4fd7e04f4e4e46f0cdd4f3cf4521587d05ac5f7"
    "d45fe91adc5d7cf6b940bdf2f8cc559e7bbb5b5619c7ebcee530f4d4e4e0a45"
    "aa8e9e8a491915e4e7978e142e285c940701166c5e23c2ec7d007f7c7cdcf0"
    "2fb561cd55cf9d79c1a54bc2975dbffa8ac40661705a8baf87f6af3e346fc1"
    "67df8f03bf61cd55cff1d3edc1872df1e3670308c12fa8d47a19062a1c0924"
    "e3672b838a5756449ec9217ce3553fd85170fa607c7cdc3cf3c31b1f070038f3"
    "824b9784f736acb9eab9f065031b000008d05b8baf9f376ca0bf4b07f0cfbc"
    "e0d22561bc9ef9e18d8f8f8f8f9bc9c9c98c655ff1e11b7690688b539b9a"
    "2d62dac1040869c9c097dd35a4f64f4d4de1d4d494f840fec5f897ce84400bc"
    "27ca17cf6ddeac0d7b70863c94d811c789f9db5792ab093329b6ebf4f5c82"
    "4eb21fcedebd7b5153ff9e3d7b8af7af13824a36980fe02b7bcf99b00a7c00"
    "803d7bf698c002618c1d0b68adefbe267f04ba970080b0fa377a8208675cfbc"
    "85377ffc5b223272727616a6a0aa7a7a771f7eedda64ac2cebce0d225e1cb47"
    "21f00310fd82f6af3e3467fd822e29bfee56bb77ef36071f7c307946a5430e"
    "39048ebee89b4fb96cae02becb8519a697ef6649958459d79e26507fd0fe898"
    "989dafb37360973c92fe8c1de77bae5c4c484092c104c011ff7e40274cf00dd"
    "9b80e00958b1c2483430989e9ec6898909dcbb776fa3fbcf1bbfa083bd6f4a"
    "f985bc8a999898c0e9e969949ace1a63a9ee67c33301a05aa3c5e5c1042bb"
    "ef4d8f6afbdf325474d4d4de1cccc0c4e4e4e1a38a8d95dab4c421082fdde"
    "2454687d10e65e80678eb5999998898ef5eb2fbbeb8962a7b5d96000aef5b11"
    "a85f5eb7bef2dbf78dc3380e976a6af6412ce3a7f65bd49d8cfed7dbfe087"
    "c86a6262c24c4f4fe39baffdcee32902932cd0cbd14314a05aa6323b44be55"
    "ddcccc0c7a89edc9c798337e41077bdf2be517c24013c634d13d33c1bc1d2"
    "d0cd909d42d539d5368537dba25b874b3ddda6eb7dd03f778941247fb955f"
    "d0c0de57315bb7c7cccc0cb6db6d7cdf9aed5b81db7ab534cf358b1b76144"
    "0249a25a7ae998c9288e0b3db7efd116b6d5fc51e5526619fe70b0a5a5f0"
    "77ebf1f67adc5bfd9f0ab47086ccac5d8f2025d80590803c30759dfc93275c"
    "9b6a94add12acf9c5913f18c478ef577e414d72076d3b527ebf5acf8fcffda8"
    "f503e08dad230b902b00e92311647a83bedc25db354a6e67cd9207250461402"
    "b4dc230fd820ef61e6d7ba05aaf49d753418dd687d07cc80ca07be347dba3"
    "3c51a23604ca1ab420944cc250fd821a7bcfb57e18e07bfbca9a50db72ff67"
    "9a2d06a0721f7da9f5bc373e0c5d08d0b69f13b5058314821a7bafb57e28"
    "e06be6552617d4de62ddca406f89a0a0ecaa4954dabf0006b0a561332108da"
    "e78560c940934635c99d61527e35f8be122b94e41300206b324db33119c475"
    "df33010aadaf29531e9220702138d3670f8b42a0d9a109f00a7c0ebc06ffc"
    "a65a7166ff7b7db1eead307208773009fd0d7668ad87c7612417153041d7"
    "f2a3b34db42506912baf50b3ad8fb2acabf72d9a970d24b7fadf8af4a30"
    "ba4dc069df2b9a649d1b18761e20db0747cf4c7901b0767604a004484f7e"
    "4117f69e031fc0af3a8210f42e08a4c26d9efee5dbe25037cd3afac90390"
    "d807876b7dec4eba8f8e921034ca177488efebec7d1df8dd9c531d0450a6"
    "f5626b9a3e9a75999ec0675a2f3641f20ea0d8ac691f1c7ba7db4208329"
    "3a063fb0af0c3b50000af3df5ec25fcbe9cf6f971dceb96ade3ff4a4cd0"
    "abd72533ae49eb85991876146089b2ad5fe2ee57a418c2d66dfc34f863ddd"
    "7ff0e00004e3e7d0500c0120080ff7c689d8812a273d805e5bff6d4b39784"
    "fbdef52f570200c08f3e7d6f117cfd4cc7bd6ed9ba9ffcfbb6b3b5107ce"
    "2d12dddcb00f105b9e41282d87b08d87b1e20d37a625ba0a53051570f0ff3"
    "dfbaafff1d9c7cfa8a003e68f06afd8206e087a3f41955e0d7bed7e47b09"
    "02607f2b6d8419b794a1e13280b4f7c4178e83defa4c8732c33aeefec6554"
    "55038889a0944bea010df6be0071ed7f7321e41c110bd1262de329686cd00"
    "203d51a2bc655cc9110cbb980cfa5f27f0b9100450b55fb07ef51570e2296"
    "f81134f790bcc06f84dc7a3180616a2024b36dba565783e80e52b8252e6cf"
    "5a4a8b904b0f3d0406b867cdd58dc02fb1410039805f45f94394802ea20"
    "00bd86aa5f1b6183382e5fccb9019a0a4f572b74bca16a9d080ffeb05fc"
    "12c81cfc7e0eeee83579afc9772ce502b8ada7d262109a853030806d2de"
    "5fbf95ae7fdebb685dc51ece7dfbd6bae817bd75cd333f8833a3e78df17e"
    "0e15feeee08b4fedbc3bfdc0d97fc687da3ef9a51beb2f5b1342c24e87a"
    "98861fe98dbe582510db8082378f22507ec0004cc07d375dbbcf81d742f0"
    "c5377f588483754cf0f02f77c3258fdcdffd58305b0f68c42450293b3b6"
    "41f80f2ae30443e3fa01e80aa9c98ee8ffbbff9b9fd0a7c0d6ca74c5f6"
    "08bdec6418d2f8619d7908fc19e95aca73090d83ed07263439b66aef4c"
    "3f4c100f7dffc0ffb2df81fbcef0b0000191368f057fef09e9ec721fa7858"
    "06bb970c607f26206abd7b32a1f97e9b536dc77acd03acbfe5f3fb2df825"
    "73503a2efe8fbbfbca8310d9d4b0dda7e045244679783edc4410a94d6328"
    "a52aa9a28f702f03b0e1d6ebe604f89a0d4a427ce6bb3e3a90d091c0026"
    "00bf816b2b1f9430f33f0ddd70358628b43a5d65b9e0ed67d64bb4cedce"
    "35f0eb8e934f5f011b6ebdaefb14b708bc0a6136c7817aabc1e8d10410c"
    "b4aea88958532405d3b811b6ffb421cb4f9749c7cfa0ad8f0afff080000"
    "67bce3c3bd780192f251d2bf2c1819b60960a1a00c03e5feb6dd86811bbf"
    "75fdbc035e0b4110f2337ebfbb1245229b5a37c771c7c26ce0b097868595"
    "415902886b3d15c2c0faa4c77c075f0bc2c66f5ddf3c11a4167ff0a5f"
    "9a094b05b4faba792305bb04700726a584b635dca73d3da2f1e30e07321"
    "d8b4f68b5da48219f84cbbc26290a87a5d66037b6c10111e26a57d49952"
    "b91770a3b39810facfdd201073e178207d67ea9b31358073e13955e52c13"
    "d4f074badb799d693d8a2b63cfdf9c0ed5f3e60c1174270fb97eba7834"
    "b8b3fd80ee2d0e39a809e9cc02865ba572cb1f2701e9716f2009beff8ca"
    "bcf4f4fb118207bffdcf0000b07cc507cad40fe492413e236843cf479f07"
    "20ead82770700c90697d280e091eaab551283ff4e0e10000f0bd8d6b0188"
    "60f31d5fa92cab3ad085e0e4d35738e52072e30500efbe99fb7bcae9d3"
    "4539b351134899d67b5b8f4ceb439a52e50836dff9d505e01b08c2e63bb"
    "f2a7d2ec6fc71610eefca42857cc0d04c80aa0a269efcb124b61b084ec"
    "09f6ffc2db8eea4471d136cba6301e506c7d49eff83f7dd71188069c55e9"
    "fd18a62096c5d993d180150395f102107723f20cc59834d9942709b93221"
    "af8c8f78e862f9ff93ff1366f587ece02caeaf8fee6bbe2eb0b6e9c0130"
    "0e790274eb30c35eef6a512e64dbc7d6e0d750006a2f222571b1535c104f"
    "929501d65b9b3fbbff37e09f7eef7fb32fbb70c8e38fd74c011ae336f60"
    "860fb9eab184d2fa4e9e166f300c51346aa4fa2e275a4c2400088ad621"
    "0d9aa55bfe918852d8ad19531ffe9bd8b816c1bbef2d617169056c705d"
    "f9870e3655a407ed77722003408bc049c54d14d75f1ad5a3b5860859186"
    "691fe2f17c005ba71e9df7ef9d94b8ed9471ce201a2fc5230044f081752"
    "ff2f772ff92fd4a8d90a24095e3d1f2235275ea4a6f7193165902940a2b"
    "a9aa05bb8ec3b96a14a8380114f66d61dfcb2b088289e043003f3000f3"
    "ab52734e94e0eb85a3c541a1a209a0cc90a4c2933c2bc9bccde807a492"
    "1577322280c5b4900531828f340d60461c23501bc8220019c0b896c080a"
    "839c00ac98e9b9dd44c38512193c6264f10f5f5523090f85e5b2ce4422"
    "d7729118340b2b93e412ae688d3b60060fcbe6d7effeec8948080e8e81f"
    "8c11db3c8646dd6e12880973197cbdaf34c9a5e54e8a47ea427dc0d250"
    "926c53cf3a568541a5982bf226004c3acfb4129d5904349e01c0f83a47"
    "f2335f354454d51f47090ba104175b856b78828bed9c5895860dd3dfc83"
    "e93f43e3dde1d16d3b6ec331da5a79389edcf19c18f7bb519df9ddd3a"
    "61e160134ac1a41afaa332058c08e577df8ed85c3311cad8c2b27d03b34"
    "f624e2105efd51880b605c4168041203b0360bc9098403ac8661809d0b4"
    "b29473357024b74320a981956c18f7bef1c0b65a45a6898eae49c28fca"
    "9c20e533a341b3139b51aae4a5144813dbc239697ed8e935804f805eeb"
    "23cb1256982dadc56160955d8bdb3e9ad6417e7f4003600ca2698141f7"
    "13cd41685a2368cc0862eba0f6e8e9ef010038e2b4f3c6a28667c050ac"
    "1002bf9419e340b6fd0492b7fdb1a98155124cc2ce16859acaf42d78a"
    "a203cb5ab95883a5e2f1b34146c7de9330b02c8bd02082ce9fd0307bc"
    "370dd69b596f0a92b78fd2f7f2af5f78fad1550000ad1d9b6e206a4f"
    "93b53364db334076868866c05a4b60db218334127acea4755d051570229"
    "8d187655f586f308f81dac41a02e3de33e8b7b20fd4ca363907ebb412"
    "337a511f40b58e1e969223488246b55cf1508af7e489661eab85c79910"
    "93331711b302eec1c4aa6e56dc89603ce573939f26d51cdbc9cae034f"
    "fa29dd590b0517563a28cdb6d1cc9f24b3ecfe7a91f8117f8656b535"
    "4356af88e367aae0e7f020a9c6f30968c1322906db3cdc93dd58201684"
    "9c7aad6c3670d2948974b450dab169e34b9e52c60e6eb042642028496"
    "94701e151903ba5a2afa25deb7d57d9603b80e589fe5f17bfbc57d99b1"
    "dad4d9628da014e924dac4ac567a8811d1714ce5799c5852d67c862ca"
    "905a2cc07e0210e054f374d14810f0bc15a4033e2cfb1b1f7410a6bb0"
    "16b87801e6730e951323a5c99396a9f637bcc6a18e44300189d892b63e"
    "080bcf8e6102cb997cc31cb7f07b1a3be4a68120ef0806ac3057442e3"
    "ac6255e2d22e6eb036a2d44344114d16d136cdc7ee1681011118ccbe5"
    "221af3fcd3ff458b475ff3c2cec7b6bce8e5472d4f5c906f234a255b"
    "4d89ec84cdf071af7b8af071183e366e822d7f77af83fd4cd7a0bf07c"
    "67fe9d1d2069ae99e697bd4742aa67a3b64cf8a7cfd33a6f790bd17ae"
    "81940823be236b70ec42c8ebaf0f53bdc8ee57061f0ae03ba5197fe"
    "63167ff7fb6e906226b89c8dbfae874d9a871fed2111011377acfdff"
    "9e581dc11ca8bfe89999a382c314040f739f1e1f54653c13bc64895c"
    "273e61b22a15a0d130b23d963f386097a058d4110350a625145726489"
    "8fb4d238d2c9149e1bb004594e1c495644f1cfb47e6e3fded328a0317"
    "d2632662d4cfd16ab81439306d6ae23269049303cb49ca6b3edc39d08"
    "46b94444838006d1180444f3fcd35b69f1e8092fec7c7ccb8b8e386ab"
    "9d679dec038d02089840a0a790b9f86c200e55acb37bda438486c6f64"
    "629a0d58f89dbd063ed0c8b296989e27c6e129bf81c0de63a4c7bf03"
    "6f9a1937ed0b4cc405903145145e60491e9066d452be451c7770c79f"
    "0ddaffc06ae75c510cb72213b8e6cdc43c36d05100b292aea0f9e43e9"
    "f2c2011b2382aa46ba1a25f3da9e25114f98fc06708996755a7f5d13"
    "f504ca1b55e78502a654bc96c11d3b8f07072cd3d46a6a89e7645669"
    "b0178a58e4c2429e6612d5f04d310d7fa52b54fb9f0365002011191"
    "a77c8a7ddb48ed334840448e01402bbdf702c26b40e399c051c2f34fff"
    "84168f9e30fecc135b0e3de255cba9140a9672f87a3e82e50ea28688"
    "bd2e892906a753e51123cfc8694791f26b82e388c00a57480a0f2aa71"
    "359762f7b069d3167cfcd3382ec1a0ae611797e4132244169e1675e1"
    "c3afeece349fb5db2a5ed35dfe5dbc3844b2a1d897734dc37664d7e"
    "620c49a9e98f25224baa39e07f7ff7ee55b24194dfc44047232a51c"
    "446df6983a554106b49fc6e8962c7f460d59285e39d32ca2623d23d9"
    "ba6a6f8996ca975e11a22de064f6dc6ecb5d8065f8699adb87d0ba9fb"
    "59b69e8f30dff38958f23e4b2c51d63432801fb5df397f966126f0e"
    "4f56494368fd6e92ae043ed5e539cb6b300649db4e5d542bc7954e815"
    "487c5f3b2acd3a53e574261585474516597144bea132b1f235f74cb6c"
    "c1401044b927ad533043da05216b1005c3667cfb28a32620b5a6e3bee"
    "0dcccbc0bdf6477c8832959173c3fe552bcd3a84fc73fc11ec0230bb1"
    "066291001b1b5fbe9ad76f12b8f1f7f76fb96430f7fd5f2ea389c6a4"
    "b9b8583d420155b9d212c2c582195d4a9994124b63143d5dc81aec5c"
    "fdae5977af851b98f0fcf97504d3a39ef03e4cedbb36bfb2a008091"
    "a71fbc1188da44b6ed1dbe3600b51313f8bd3d9920049fa0050174e"
    "f92a2f801c917080281c82406b1f5fcce47ede2571ebfe7d9ed5b0e"
    "7dd991cb6346af502e56075c95775b59ee5468945c16c0bc93562e2c"
    "507fbdcafd535d62299b7ba09ab904555769f3f476a909141131f037"
    "df441e7c0f3c8bff9d318d1b0dc5c74d0fda4af39051fd115274245"
    "9003009084449c0d6ee67b6d9c35e71dc9e9f3fe98520070e11fb9a8"
    "0a9159e3ae06b06be96ada0506c51a3c14d802b5d43158e5d9df044f"
    "0776eb9d901efc08fdaeffdb5a4fdcc0cf08983e4ab662c10ab39bdf2"
    "b710fd4ca17bdd0234619670048c69219a9199979ff687e1fbbef4f567"
    "8dd503c9f2e1aa52a7a97f50071cf5223c1574abc12fad8b94d74343"
    "ad6f4af9dee1fbf913d1e1f3e0cf80b56da2f60c59eb67fc8230d8"
    "b677d8db9412439678030772d32e69ae5139018c05f4cf1827c6e80f"
    "015bbb776eb387bde25800803dbb9eda72e8cb7e7b7913ada7527848"
    "54ede865edd129af976b283c65474f67ccbdc3d5c94c5408dc20b5de"
    "837f0b916d3bf06dd0fa68f329646d63ab366f06f21a371ea344d31e"
    "270642511fa231211700c6b4103c1378cd07342dc7068e19665e7eda"
    "1f70bc5ffaba33c68a1e7e5d754f8339fb66b6bed99c7de91adbc06"
    "4d4ddaf1badafaa55e05a1fc00f9aeeb5be4d6467c87acd87201841e"
    "3adcf00923705c04c01f1603cb2001702e3eb94d04f1ab5bc30b89f0"
    "647104d30092df482e05f8f4c1ff1c677f087ffcd13df34c66d7dee"
    "287641ff00b5e05779e455c2a341280a534d38d7a94ab72aa953753"
    "f0dfc41cffcdb6d441e701ba8de06aa6f83a5197234c5a93f55da50e"
    "82a20e7ce65715ad11788d384de27f0b383605a68d0038f4208bc7fd0"
    "4274ef4f1f7ecadb4b85872f79edf2b1d9d0faead2b29cbea9e633eb"
    "6c7f067c83f08e5f23123a1cf867bfb3167c78e7b45c83ef327f64a9"
    "0dbed22724eb28965bbb440eb3fd24ea253ab040ac56f44210d9c00b"
    "04170203184c41feded4e1bffb7658381a1d073ffbddb5694a37da7ae"
    "bc19f29bdc7b59e5252a840fd290faf04804dd9550981330b06e3e4"
    "bc315ed30d82f30b0023337021301004c30bd2d4d293deb600b5077"
    "cd7c3770ae0c8dbf1a4e936867bd6b6c917587a2148ce1fb010b01"
    "efc4c000aa620260562992a86ca0c2e0480064df40d98f6f39f4e489"
    "80018166efa2453323f323c15648573004f5d01a3f3d9a1462bd89f90"
    "b3b74c006242476abfff09d4266b637a9ea7ea8962e227958389a9c"
    "6f470a5a561c85e919f33235f961c96a4596e465d818bf5ab5962053"
    "e21a0a1b0b08dd00252f01f42698f498b077ca94f9cc70df9a7c272e"
    "3b9719462d318867901485aea42364b60d3444e98d3f7d41e9c3b201"
    "b327c6d3e59077c0a8dc4bc7fa1660ea02400b2008f02a66cd23dc8"
    "1382c5e4e09a34cbed0ae908c0b8056e488864c8038f848690dc3a2"
    "88ca023221a22ee87846a9279c000d96e9a1452b2313e4faf05f081"
    "cedbd9df40f493a1e4f0958a07aa0b25ab06b3833f1097b120422cc0"
    "3308a9702fd4120a33c10bf9526481006030dd570a40fa5be28439200"
    "044859024178050112b01cc29bdc40e94c007097e07bbdf44004afe00"
    "1782f086093383c00a47c46be53cb2f7c4f29768ffd34a896ca1d6dc"
    "140039dbcf9330d10ff0f63ad9eee81744678e09847c9dc2bad898a1"
    "14ef97c06f3298554cc01dc3e420422acb8d6c009a1dc22aa4786ea"
    "cc2e3e968486aaf97eacd211390745d261452333db98023300190d0f"
    "2641a627a97403a7ac9e11309888e5b8a7623009a093855c75051661"
    "0253b449311b38bccebd726c0ff513d21d63ee6bec5bafa0d12d35d"
    "a472c5292a48f57b29872fb55c66f4e4664dacb20bcaab777a1c3954"
    "b92241cd28ec3567836831122308d628f81412f5cc0780fd9f09aa0a"
    "2165c1978e0a82cd167d7823f03c9e07a1f569765f4f3a14f2defda9"
    "4eee8933cb8ccc3cb0fa02c05cbb6b81174295095cf648fba1005474"
    "b3205173c7cb80ea05416837b1ae90c99750f6be3a0281c170678549"
    "6053c5d27b9711042b3c01518accad8a601c6d0070ce10004187098d"
    "e41b90ced1277b2e9c467e1dc9b2eac6943f081aad1202ed1b809a6"
    "ac682ef0079c68f857d50047c2ee60144564882968789241882f90e"
    "4490d9fa3ec00700f87f8c107ec2797970300000000049454e44ae426082"
)


def make_favicon_png(size=96):
    def clamp(v):
        return max(0, min(255, int(v)))

    def mix(a, b, t):
        return tuple(clamp(a[i] * (1 - t) + b[i] * t) for i in range(4))

    def over(dst, src):
        sa = src[3] / 255
        da = dst[3] / 255
        out_a = sa + da * (1 - sa)
        if out_a <= 0:
            return (0, 0, 0, 0)
        rgb = tuple(clamp((src[i] * sa + dst[i] * da * (1 - sa)) / out_a) for i in range(3))
        return rgb + (clamp(out_a * 255),)

    def in_round_rect(x, y, left, top, right, bottom, radius):
        if x < left or x > right or y < top or y > bottom:
            return False
        cx = left + radius if x < left + radius else right - radius if x > right - radius else x
        cy = top + radius if y < top + radius else bottom - radius if y > bottom - radius else y
        return (x - cx) * (x - cx) + (y - cy) * (y - cy) <= radius * radius

    def in_poly(x, y, pts):
        inside = False
        j = len(pts) - 1
        for i, (xi, yi) in enumerate(pts):
            xj, yj = pts[j]
            if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / ((yj - yi) or 1) + xi:
                inside = not inside
            j = i
        return inside

    def dist_line(px, py, ax, ay, bx, by):
        vx, vy = bx - ax, by - ay
        wx, wy = px - ax, py - ay
        c1 = vx * wx + vy * wy
        c2 = vx * vx + vy * vy
        t = 0 if c2 == 0 else max(0, min(1, c1 / c2))
        x, y = ax + t * vx, ay + t * vy
        return ((px - x) * (px - x) + (py - y) * (py - y)) ** 0.5

    pixels = [[(0, 0, 0, 0) for _ in range(size)] for _ in range(size)]
    scale = size / 96

    def sx(v):
        return v * scale

    for y in range(size):
        for x in range(size):
            xx, yy = x / scale, y / scale
            color = (0, 0, 0, 0)
            if in_round_rect(xx, yy, 8, 8, 88, 88, 20):
                t = (xx * 0.45 + yy * 0.7) / 105
                c = mix((74, 163, 223, 255), (8, 63, 118, 255), t)
                glow = max(0, 1 - ((xx - 31) ** 2 + (yy - 20) ** 2) / 3600)
                c = (clamp(c[0] + 28 * glow), clamp(c[1] + 28 * glow), clamp(c[2] + 28 * glow), 255)
                color = over(color, c)
            if in_round_rect(xx, yy, 13, 12, 83, 43, 17):
                color = over(color, (255, 255, 255, 28))
            if in_round_rect(xx, yy - 4, 18, 31, 78, 69, 7):
                color = over(color, (0, 0, 0, 48))
            body = in_round_rect(xx, yy, 18, 30, 78, 68, 6)
            if body:
                t = max(0, min(1, (yy - 30) / 38))
                color = over(color, mix((255, 251, 239, 255), (226, 205, 162, 255), t))
            if in_poly(xx, yy, [(20, 66), (42, 47), (48, 52), (54, 47), (76, 66)]):
                color = over(color, (234, 214, 170, 255))
            if in_poly(xx, yy, [(20, 32), (76, 32), (48, 53)]):
                color = over(color, (255, 253, 246, 255))
            if body and (abs(xx - 18) < 1.2 or abs(xx - 78) < 1.2 or abs(yy - 30) < 1.2 or abs(yy - 68) < 1.2):
                color = over(color, (178, 146, 90, 210))
            for ax, ay, bx, by in [(21, 33, 48, 53), (75, 33, 48, 53), (22, 66, 42, 47), (74, 66, 54, 47)]:
                if dist_line(xx, yy, ax, ay, bx, by) < 0.9:
                    color = over(color, (167, 126, 70, 190))
            if (xx - 65) ** 2 + (yy - 53) ** 2 <= 6.4 ** 2:
                color = over(color, (189, 57, 47, 255))
            if (xx - 65) ** 2 + (yy - 53) ** 2 <= 3.2 ** 2:
                color = over(color, (232, 108, 89, 190))
            if (xx - 31) ** 2 + (yy - 22) ** 2 <= 5.5 ** 2:
                color = over(color, (255, 255, 255, 45))
            pixels[y][x] = color

    raw = bytearray()
    for row in pixels:
        raw.append(0)
        for r, g, b, a in row:
            raw.extend((r, g, b, a))

    def chunk(kind, data):
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


FAVICON_PNG = make_favicon_png()

DB_DIR = os.path.dirname(os.path.abspath(DB_PATH))
BACKUP_DIR = os.path.abspath(BACKUP_DIR)
os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

_RATE_LOCK = Lock()
_RATE_BUCKETS = {}
_LONG_POLL_LOCK = Lock()
_LONG_POLL_ACTIVE = {}
_MAIL_EVENT = Condition()
_MAIL_EVENT_SEQ = 0
_DOMAIN_CACHE_LOCK = Lock()
_DOMAIN_CACHE = {"expires": 0.0, "domains": []}
_DB_CONFIG_LOCK = Lock()
_DB_CONFIGURED = False
_DB_ACTIVITY = Condition()
_DB_ACTIVE = 0
_DB_MAINTENANCE = False
_CLEANUP_LOCK = Lock()
_CLEANUP_LAST = {}
_HEALTH_LOCK = Lock()
_HEALTH_CACHE = {"expires": 0.0, "data": None}
_DNS_CACHE_LOCK = Lock()
_DNS_CACHE = {}
_BACKUP_LOCK = RLock()
_INTEGRITY_LOCK = Lock()
_INTEGRITY_STATE = {"checked_at": 0, "ok": None, "message": "尚未检查"}
_WEBHOOK_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ferret-webhook")
_WEBHOOK_SLOTS = BoundedSemaphore(128)
_HTTP_SLOTS = BoundedSemaphore(max(1, HTTP_MAX_CONNECTIONS))
_SMTP_SLOTS = BoundedSemaphore(max(1, SMTP_MAX_CONNECTIONS))


def now_ms():
    return int(time.time() * 1000)


def safe_log(message):
    try:
        clean = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", " ", str(message or ""))
        print(clean[:2000], flush=True)
    except (BrokenPipeError, OSError, ValueError):
        pass


def private_file(path):
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass


def sha256_hex(value):
    return hashlib.sha256(str(value or "").encode("utf-8", errors="replace")).hexdigest()


def constant_time_equal(a, b):
    return hmac.compare_digest(str(a or "").encode("utf-8"), str(b or "").encode("utf-8"))


def rate_check(key, limit, window=60):
    if limit <= 0:
        return True, 0
    now = time.monotonic()
    with _RATE_LOCK:
        expires, count = _RATE_BUCKETS.get(key, (now + window, 0))
        if now >= expires:
            expires, count = now + window, 0
        if count >= limit:
            return False, max(1, int(expires - now))
        _RATE_BUCKETS[key] = (expires, count + 1)
        if len(_RATE_BUCKETS) > 8000:
            stale = [k for k, (exp, _) in _RATE_BUCKETS.items() if exp <= now]
            for k in stale:
                _RATE_BUCKETS.pop(k, None)
            if len(_RATE_BUCKETS) > 8000:
                overflow = len(_RATE_BUCKETS) - 6000
                oldest = sorted(_RATE_BUCKETS.items(), key=lambda item: item[1][0])[:overflow]
                for bucket_key, _ in oldest:
                    _RATE_BUCKETS.pop(bucket_key, None)
    return True, 0


def acquire_long_poll_slot(ip):
    if LONG_POLL_MAX_ACTIVE_PER_IP <= 0:
        return True
    key = str(ip or "unknown")
    with _LONG_POLL_LOCK:
        active = int(_LONG_POLL_ACTIVE.get(key, 0) or 0)
        if active >= LONG_POLL_MAX_ACTIVE_PER_IP:
            return False
        _LONG_POLL_ACTIVE[key] = active + 1
        return True


def release_long_poll_slot(ip):
    key = str(ip or "unknown")
    with _LONG_POLL_LOCK:
        active = int(_LONG_POLL_ACTIVE.get(key, 0) or 0) - 1
        if active > 0:
            _LONG_POLL_ACTIVE[key] = active
        else:
            _LONG_POLL_ACTIVE.pop(key, None)


def signal_mail_change():
    global _MAIL_EVENT_SEQ
    with _MAIL_EVENT:
        _MAIL_EVENT_SEQ += 1
        _MAIL_EVENT.notify_all()


def wait_for_mail_change(timeout=25):
    with _MAIL_EVENT:
        start = _MAIL_EVENT_SEQ
        _MAIL_EVENT.wait(timeout=max(0.1, float(timeout or 0)))
        return _MAIL_EVENT_SEQ != start


def invalidate_domain_cache():
    with _DOMAIN_CACHE_LOCK:
        _DOMAIN_CACHE["expires"] = 0.0
        _DOMAIN_CACHE["domains"] = []

@contextmanager
def db():
    global _DB_ACTIVE, _DB_CONFIGURED
    with _DB_ACTIVITY:
        while _DB_MAINTENANCE:
            _DB_ACTIVITY.wait()
        _DB_ACTIVE += 1
    con = None
    try:
        con = sqlite3.connect(DB_PATH, timeout=30)
        con.row_factory = sqlite3.Row
        if not _DB_CONFIGURED:
            with _DB_CONFIG_LOCK:
                if not _DB_CONFIGURED:
                    mode = con.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                    if str(mode).lower() != "wal":
                        raise RuntimeError(f"SQLite WAL mode unavailable: {mode}")
                    _DB_CONFIGURED = True
        con.execute(f"PRAGMA synchronous={SQLITE_SYNCHRONOUS}")
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA busy_timeout=30000")
        yield con
        con.commit()
    except BaseException:
        if con is not None:
            try:
                con.rollback()
            except sqlite3.Error:
                pass
        raise
    finally:
        if con is not None:
            con.close()
        with _DB_ACTIVITY:
            _DB_ACTIVE = max(0, _DB_ACTIVE - 1)
            _DB_ACTIVITY.notify_all()


@contextmanager
def exclusive_db_maintenance():
    global _DB_MAINTENANCE
    with _DB_ACTIVITY:
        while _DB_MAINTENANCE:
            _DB_ACTIVITY.wait()
        _DB_MAINTENANCE = True
        while _DB_ACTIVE:
            _DB_ACTIVITY.wait()
    try:
        yield
    finally:
        with _DB_ACTIVITY:
            _DB_MAINTENANCE = False
            _DB_ACTIVITY.notify_all()

def init_db():
    with db() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS mails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            to_email TEXT NOT NULL,
            from_email TEXT,
            subject TEXT,
            text TEXT,
            raw TEXT,
            received_at INTEGER NOT NULL
        )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_mails_to_time ON mails (to_email, received_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mails_time ON mails (received_at)")
        con.execute("""
        CREATE TABLE IF NOT EXISTS aliases (
            email TEXT PRIMARY KEY,
            note TEXT,
            created_at INTEGER NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS mail_domains (
            domain TEXT PRIMARY KEY,
            note TEXT,
            token TEXT,
            created_at INTEGER NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mail_id INTEGER NOT NULL,
            filename TEXT,
            content_type TEXT,
            size INTEGER NOT NULL DEFAULT 0,
            data BLOB,
            created_at INTEGER NOT NULL
        )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_attachments_mail ON attachments (mail_id)")
        con.execute("""
        CREATE TABLE IF NOT EXISTS operation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            actor TEXT,
            action TEXT NOT NULL,
            detail TEXT,
            created_at INTEGER NOT NULL
        )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_operation_logs_domain_time ON operation_logs (domain, created_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_operation_logs_action_time ON operation_logs (action, created_at DESC)")
        con.execute("""
        CREATE TABLE IF NOT EXISTS cleanup_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            deleted_count INTEGER NOT NULL DEFAULT 0,
            reason TEXT,
            created_at INTEGER NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS failed_mails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mail_from TEXT,
            rcpt_to TEXT,
            reason TEXT,
            detail TEXT,
            created_at INTEGER NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS backup_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            size INTEGER NOT NULL DEFAULT 0,
            kind TEXT,
            created_at INTEGER NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS service_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS domain_usage (
            domain TEXT PRIMARY KEY,
            mail_count INTEGER NOT NULL DEFAULT 0,
            storage_bytes INTEGER NOT NULL DEFAULT 0,
            alias_count INTEGER NOT NULL DEFAULT 0
        )
        """)
        def add_col(table, column, ddl):
            cols = {r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in cols:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        add_col("mails", "is_read", "is_read INTEGER NOT NULL DEFAULT 0")
        add_col("mails", "read_at", "read_at INTEGER")
        add_col("mails", "starred", "starred INTEGER NOT NULL DEFAULT 0")
        add_col("mails", "pinned", "pinned INTEGER NOT NULL DEFAULT 0")
        add_col("mails", "updated_at", "updated_at INTEGER")
        add_col("mails", "domain", "domain TEXT")
        add_col("mails", "verification_code", "verification_code TEXT")
        add_col("mails", "has_link", "has_link INTEGER")
        add_col("mails", "metadata_version", "metadata_version INTEGER NOT NULL DEFAULT 0")
        add_col("mails", "stored_bytes", "stored_bytes INTEGER NOT NULL DEFAULT 0")
        add_col("aliases", "domain", "domain TEXT")
        add_col("aliases", "share_token", "share_token TEXT")
        add_col("aliases", "share_enabled", "share_enabled INTEGER NOT NULL DEFAULT 0")
        add_col("aliases", "share_created_at", "share_created_at INTEGER")
        add_col("aliases", "share_last_used_at", "share_last_used_at INTEGER")
        add_col("aliases", "mail_count", "mail_count INTEGER NOT NULL DEFAULT 0")
        add_col("aliases", "latest_mail_at", "latest_mail_at INTEGER NOT NULL DEFAULT 0")
        add_col("aliases", "activity_at", "activity_at INTEGER NOT NULL DEFAULT 0")
        con.execute("UPDATE mails SET domain=LOWER(SUBSTR(to_email, INSTR(to_email, '@') + 1)) WHERE (domain IS NULL OR domain='') AND INSTR(to_email, '@')>0")
        con.execute("UPDATE aliases SET domain=LOWER(SUBSTR(email, INSTR(email, '@') + 1)) WHERE (domain IS NULL OR domain='') AND INSTR(email, '@')>0")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mails_domain_time ON mails (received_at DESC, to_email)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mails_state ON mails (is_read, starred, pinned, received_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mails_to_state_time ON mails (to_email, is_read, received_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mails_domain_time2 ON mails (domain, pinned DESC, starred DESC, received_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mails_domain_state_time ON mails (domain, is_read, starred, pinned, received_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mails_domain_code_time ON mails (domain, verification_code, received_at DESC) WHERE verification_code IS NOT NULL AND verification_code <> ''")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mails_metadata_version ON mails (metadata_version, id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_aliases_created ON aliases (created_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_aliases_domain_created ON aliases (domain, created_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_aliases_domain_activity ON aliases (domain, activity_at DESC, email ASC)")
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_aliases_share_token ON aliases (share_token) WHERE share_token IS NOT NULL AND share_token <> ''")
        con.execute("CREATE INDEX IF NOT EXISTS idx_failed_mails_time ON failed_mails (created_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_cleanup_runs_time ON cleanup_runs (created_at DESC)")
        cols = {r["name"] for r in con.execute("PRAGMA table_info(mail_domains)").fetchall()}
        if "token" not in cols:
            con.execute("ALTER TABLE mail_domains ADD COLUMN token TEXT")
        add_col("mail_domains", "owner", "owner TEXT")
        add_col("mail_domains", "enabled", "enabled INTEGER NOT NULL DEFAULT 1")
        add_col("mail_domains", "token_disabled", "token_disabled INTEGER NOT NULL DEFAULT 0")
        add_col("mail_domains", "retention_hours", f"retention_hours INTEGER NOT NULL DEFAULT {RETENTION_HOURS}")
        add_col("mail_domains", "cleanup_max_mails", "cleanup_max_mails INTEGER NOT NULL DEFAULT 0")
        add_col("mail_domains", "alias_limit", f"alias_limit INTEGER NOT NULL DEFAULT {DEFAULT_ALIAS_LIMIT}")
        con.execute(
            "UPDATE mail_domains SET alias_limit=? WHERE alias_limit IS NULL OR alias_limit=10000",
            (DEFAULT_ALIAS_LIMIT,),
        )
        add_col("mail_domains", "mail_limit", f"mail_limit INTEGER NOT NULL DEFAULT {DEFAULT_MAIL_LIMIT}")
        add_col("mail_domains", "storage_limit_mb", f"storage_limit_mb INTEGER NOT NULL DEFAULT {DEFAULT_STORAGE_LIMIT_MB}")
        add_col("mail_domains", "brand_title", "brand_title TEXT")
        add_col("mail_domains", "brand_desc", "brand_desc TEXT")
        add_col("mail_domains", "default_alias", "default_alias TEXT")
        add_col("mail_domains", "theme_color", "theme_color TEXT")
        add_col("mail_domains", "webhook_url", "webhook_url TEXT")
        add_col("mail_domains", "webhook_enabled", "webhook_enabled INTEGER NOT NULL DEFAULT 0")
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_domains_token ON mail_domains (token) WHERE token IS NOT NULL AND token <> ''")

        usage_row = con.execute("SELECT value FROM service_meta WHERE key='domain_usage_version'").fetchone()
        if not usage_row or usage_row["value"] != "1":
            for trigger in (
                "trg_mails_usage_insert", "trg_mails_usage_delete", "trg_mails_usage_update",
                "trg_aliases_usage_insert", "trg_aliases_usage_delete", "trg_aliases_usage_update",
            ):
                con.execute(f"DROP TRIGGER IF EXISTS {trigger}")
            con.execute("""
                UPDATE mails
                SET stored_bytes =
                    LENGTH(CAST(COALESCE(raw,'') AS BLOB)) +
                    LENGTH(CAST(COALESCE(text,'') AS BLOB)) +
                    COALESCE((SELECT SUM(LENGTH(a.data)) FROM attachments a WHERE a.mail_id=mails.id AND a.data IS NOT NULL), 0)
            """)
            con.execute("DELETE FROM domain_usage")
            con.execute("""
                INSERT INTO domain_usage (domain,mail_count,storage_bytes,alias_count)
                SELECT domain,COUNT(*),COALESCE(SUM(stored_bytes),0),0
                FROM mails WHERE COALESCE(domain,'')<>'' GROUP BY domain
            """)
            con.execute("""
                INSERT INTO domain_usage (domain,mail_count,storage_bytes,alias_count)
                SELECT domain,0,0,COUNT(*)
                FROM aliases WHERE COALESCE(domain,'')<>'' GROUP BY domain
                ON CONFLICT(domain) DO UPDATE SET alias_count=excluded.alias_count
            """)
            con.execute("INSERT INTO service_meta (key,value) VALUES ('domain_usage_version','1') ON CONFLICT(key) DO UPDATE SET value=excluded.value")

        alias_stats_row = con.execute("SELECT value FROM service_meta WHERE key='alias_stats_version'").fetchone()
        if not alias_stats_row or alias_stats_row["value"] != "2":
            for trigger in (
                "trg_mails_alias_stats_insert", "trg_mails_alias_stats_delete",
                "trg_mails_alias_stats_update", "trg_aliases_stats_insert",
            ):
                con.execute(f"DROP TRIGGER IF EXISTS {trigger}")
            con.execute("""
                UPDATE aliases SET
                    mail_count=(SELECT COUNT(*) FROM mails m WHERE m.to_email=aliases.email),
                    latest_mail_at=COALESCE((SELECT MAX(m.received_at) FROM mails m WHERE m.to_email=aliases.email),0),
                    activity_at=MAX(created_at,COALESCE((SELECT MAX(m.received_at) FROM mails m WHERE m.to_email=aliases.email),0))
            """)
            con.execute("INSERT INTO service_meta (key,value) VALUES ('alias_stats_version','2') ON CONFLICT(key) DO UPDATE SET value=excluded.value")

        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_mails_usage_insert AFTER INSERT ON mails
        WHEN COALESCE(NEW.domain,'')<>''
        BEGIN
            INSERT INTO domain_usage (domain,mail_count,storage_bytes,alias_count)
            VALUES (NEW.domain,1,MAX(0,COALESCE(NEW.stored_bytes,0)),0)
            ON CONFLICT(domain) DO UPDATE SET
                mail_count=mail_count+1,
                storage_bytes=storage_bytes+MAX(0,COALESCE(NEW.stored_bytes,0));
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_mails_usage_delete AFTER DELETE ON mails
        WHEN COALESCE(OLD.domain,'')<>''
        BEGIN
            UPDATE domain_usage SET
                mail_count=MAX(0,mail_count-1),
                storage_bytes=MAX(0,storage_bytes-MAX(0,COALESCE(OLD.stored_bytes,0)))
            WHERE domain=OLD.domain;
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_mails_usage_update AFTER UPDATE OF domain,stored_bytes ON mails
        WHEN COALESCE(OLD.domain,'')<>COALESCE(NEW.domain,'') OR COALESCE(OLD.stored_bytes,0)<>COALESCE(NEW.stored_bytes,0)
        BEGIN
            UPDATE domain_usage SET
                mail_count=MAX(0,mail_count-1),
                storage_bytes=MAX(0,storage_bytes-MAX(0,COALESCE(OLD.stored_bytes,0)))
            WHERE domain=OLD.domain;
            INSERT INTO domain_usage (domain,mail_count,storage_bytes,alias_count)
            SELECT NEW.domain,1,MAX(0,COALESCE(NEW.stored_bytes,0)),0 WHERE COALESCE(NEW.domain,'')<>''
            ON CONFLICT(domain) DO UPDATE SET
                mail_count=mail_count+1,
                storage_bytes=storage_bytes+MAX(0,COALESCE(NEW.stored_bytes,0));
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_aliases_usage_insert AFTER INSERT ON aliases
        WHEN COALESCE(NEW.domain,'')<>''
        BEGIN
            INSERT INTO domain_usage (domain,mail_count,storage_bytes,alias_count)
            VALUES (NEW.domain,0,0,1)
            ON CONFLICT(domain) DO UPDATE SET alias_count=alias_count+1;
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_aliases_usage_delete AFTER DELETE ON aliases
        WHEN COALESCE(OLD.domain,'')<>''
        BEGIN
            UPDATE domain_usage SET alias_count=MAX(0,alias_count-1) WHERE domain=OLD.domain;
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_aliases_usage_update AFTER UPDATE OF domain ON aliases
        WHEN COALESCE(OLD.domain,'')<>COALESCE(NEW.domain,'')
        BEGIN
            UPDATE domain_usage SET alias_count=MAX(0,alias_count-1) WHERE domain=OLD.domain;
            INSERT INTO domain_usage (domain,mail_count,storage_bytes,alias_count)
            SELECT NEW.domain,0,0,1 WHERE COALESCE(NEW.domain,'')<>''
            ON CONFLICT(domain) DO UPDATE SET alias_count=alias_count+1;
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_mails_alias_stats_insert AFTER INSERT ON mails
        BEGIN
            UPDATE aliases SET
                mail_count=mail_count+1,
                latest_mail_at=MAX(latest_mail_at,NEW.received_at),
                activity_at=MAX(activity_at,NEW.received_at)
            WHERE email=NEW.to_email;
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_mails_alias_stats_delete AFTER DELETE ON mails
        BEGIN
            UPDATE aliases SET
                mail_count=MAX(0,mail_count-1),
                latest_mail_at=CASE
                    WHEN OLD.received_at>=latest_mail_at THEN COALESCE((SELECT MAX(received_at) FROM mails WHERE to_email=OLD.to_email),0)
                    ELSE latest_mail_at
                END,
                activity_at=CASE
                    WHEN OLD.received_at>=latest_mail_at THEN MAX(created_at,COALESCE((SELECT MAX(received_at) FROM mails WHERE to_email=OLD.to_email),0))
                    ELSE activity_at
                END
            WHERE email=OLD.to_email;
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_mails_alias_stats_update AFTER UPDATE OF to_email,received_at ON mails
        WHEN OLD.to_email<>NEW.to_email OR OLD.received_at<>NEW.received_at
        BEGIN
            UPDATE aliases SET
                mail_count=MAX(0,mail_count-1),
                latest_mail_at=CASE
                    WHEN OLD.received_at>=latest_mail_at THEN COALESCE((SELECT MAX(received_at) FROM mails WHERE to_email=OLD.to_email AND id<>NEW.id),0)
                    ELSE latest_mail_at
                END,
                activity_at=CASE
                    WHEN OLD.received_at>=latest_mail_at THEN MAX(created_at,COALESCE((SELECT MAX(received_at) FROM mails WHERE to_email=OLD.to_email AND id<>NEW.id),0))
                    ELSE activity_at
                END
            WHERE email=OLD.to_email;
            UPDATE aliases SET
                mail_count=mail_count+1,
                latest_mail_at=MAX(latest_mail_at,NEW.received_at),
                activity_at=MAX(activity_at,NEW.received_at)
            WHERE email=NEW.to_email;
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_aliases_stats_insert AFTER INSERT ON aliases
        BEGIN
            UPDATE aliases SET
                mail_count=(SELECT COUNT(*) FROM mails WHERE to_email=NEW.email),
                latest_mail_at=COALESCE((SELECT MAX(received_at) FROM mails WHERE to_email=NEW.email),0),
                activity_at=MAX(NEW.created_at,COALESCE((SELECT MAX(received_at) FROM mails WHERE to_email=NEW.email),0))
            WHERE email=NEW.email;
        END
        """)
        con.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_mails_attachments_delete AFTER DELETE ON mails
        BEGIN
            DELETE FROM attachments WHERE mail_id=OLD.id;
        END
        """)
        now = int(time.time() * 1000)
        for domain in BOOTSTRAP_DOMAINS:
            con.execute(
                "INSERT OR IGNORE INTO mail_domains (domain,note,token,created_at) VALUES (?,?,?,?)",
                (domain, "bootstrap", "", now),
            )

init_db()
private_file(DB_PATH)

EMAIL_RE = re.compile(r"<?([^<>\s@]+@[^<>\s@]+)>?")
ALIAS_SHARE_TOKEN_PREFIX = "alias_"
ALIAS_SHARE_TOKEN_RE = re.compile(r"^alias_[A-Za-z0-9_-]{40,120}$")

def normalize_addr(value):
    m = EMAIL_RE.search(str(value or "").strip())
    return (m.group(1) if m else "").lower().strip()


def smtp_path(value, prefix, allow_empty=False):
    value = str(value or "").strip()
    match = re.match(rf"^{re.escape(prefix)}\s*:\s*<([^<>]*)>(?:\s+.*)?$", value, re.I)
    if not match:
        match = re.match(rf"^{re.escape(prefix)}\s*:\s*([^\s<>]+)(?:\s+.*)?$", value, re.I)
    if not match:
        raise ValueError(f"{prefix} path invalid")
    raw = match.group(1).strip()
    if not raw and allow_empty:
        return ""
    address = normalize_addr(raw)
    if not address or len(address) > 320:
        raise ValueError(f"{prefix} path invalid")
    return address


def list_domains(refresh=False):
    now = time.monotonic()
    with _DOMAIN_CACHE_LOCK:
        cached = list(_DOMAIN_CACHE.get("domains") or [])
        if cached and not refresh and now < float(_DOMAIN_CACHE.get("expires") or 0):
            return cached
    with db() as con:
        rows = con.execute("SELECT domain FROM mail_domains ORDER BY CASE WHEN domain=? THEN 0 ELSE 1 END, domain", (DOMAIN,)).fetchall()
    domains = [r["domain"] for r in rows] or list(BOOTSTRAP_DOMAINS)
    with _DOMAIN_CACHE_LOCK:
        _DOMAIN_CACHE["domains"] = list(domains)
        _DOMAIN_CACHE["expires"] = now + 10
    return domains


def domain_format_valid(domain):
    domain = _clean_domain_value(domain)
    if not domain or "." not in domain or len(domain) > 253:
        return False
    labels = domain.split(".")
    return all(re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label, re.I) for label in labels)


def root_domains(refresh=False):
    candidates = list(ROOT_DOMAINS)
    try:
        candidates.extend(list_domains(refresh=refresh))
    except Exception:
        pass
    cleaned = []
    for domain in candidates:
        domain = _clean_domain_value(domain)
        if domain and domain_format_valid(domain) and domain not in cleaned:
            cleaned.append(domain)
    roots = []
    for domain in cleaned:
        if any(domain != root and domain.endswith("." + root) for root in cleaned):
            continue
        roots.append(domain)
    roots.sort(key=lambda d: (0 if d == DOMAIN else 1, d))
    return roots or [DOMAIN]


def root_domain_for(domain, refresh=False):
    domain = _clean_domain_value(domain)
    if not domain:
        return ""
    for root in sorted(root_domains(refresh=refresh), key=len, reverse=True):
        if domain == root or domain.endswith("." + root):
            return root
    return domain if domain_format_valid(domain) else ""


def is_root_domain(domain):
    domain = _clean_domain_value(domain)
    return bool(domain and domain == root_domain_for(domain))


def domain_in_root(domain, root):
    domain = _clean_domain_value(domain)
    root = _clean_domain_value(root)
    return bool(domain and root and (domain == root or domain.endswith("." + root)))


def scope_for_auth(auth):
    role = (auth or {}).get("role")
    domain = _clean_domain_value((auth or {}).get("domain") or "")
    if role == "domain" and domain:
        return domain
    if role == "root" and domain:
        return "root:" + domain
    return ""


def scope_allows_domain(scope, domain):
    scope = str(scope or "").strip().lower()
    domain = _clean_domain_value(domain)
    if not scope:
        return True
    if scope.startswith("root:"):
        return domain_in_root(domain, scope[5:])
    return domain == scope


def mx_name_for(domain):
    domain = _clean_domain_value(domain)
    root = root_domain_for(domain) or domain
    if domain == root:
        return "@"
    suffix = "." + root
    return domain[:-len(suffix)] if domain.endswith(suffix) else domain


def mail_host_for(domain):
    root = root_domain_for(domain) or _clean_domain_value(domain) or DOMAIN
    return f"mail.{root}"


def domain_of_email(email):
    email = normalize_addr(email)
    if "@" not in email:
        return ""
    host = email.rsplit("@", 1)[1]
    domains = sorted(list_domains(), key=len, reverse=True)
    for domain in domains:
        if host == domain:
            return domain
    return ""


def domain_config(domain):
    domain = normalize_domain(domain)
    with db() as con:
        row = con.execute("SELECT * FROM mail_domains WHERE domain=?", (domain,)).fetchone()
    if not row:
        raise ValueError("unsupported mail domain")
    data = dict(row)
    data["retention_hours"] = int(data.get("retention_hours") or RETENTION_HOURS)
    data["cleanup_max_mails"] = int(data.get("cleanup_max_mails") or 0)
    data["alias_limit"] = int(data.get("alias_limit") or DEFAULT_ALIAS_LIMIT)
    data["mail_limit"] = int(data.get("mail_limit") or DEFAULT_MAIL_LIMIT)
    data["storage_limit_mb"] = int(data.get("storage_limit_mb") or DEFAULT_STORAGE_LIMIT_MB)
    data["enabled"] = int(data.get("enabled") if data.get("enabled") is not None else 1)
    data["token_disabled"] = int(data.get("token_disabled") or 0)
    data["webhook_enabled"] = int(data.get("webhook_enabled") or 0)
    return data


def log_op(domain, actor, action, detail=None):
    try:
        now = int(time.time() * 1000)
        if isinstance(detail, (dict, list)):
            detail = json.dumps(detail, ensure_ascii=False)
        with db() as con:
            con.execute(
                "INSERT INTO operation_logs (domain,actor,action,detail,created_at) VALUES (?,?,?,?,?)",
                (str(domain or "")[:253], str(actor or "")[:120], str(action or "")[:80], str(detail or "")[:2000], now),
            )
    except Exception as exc:
        safe_log(f"log error: {exc}")


def log_failed_mail(mail_from, rcpt_to, reason, detail=""):
    try:
        now = int(time.time() * 1000)
        with db() as con:
            con.execute(
                "INSERT INTO failed_mails (mail_from,rcpt_to,reason,detail,created_at) VALUES (?,?,?,?,?)",
                (str(mail_from or "")[:320], str(rcpt_to or "")[:320], str(reason or "")[:160], str(detail or "")[:1000], now),
            )
    except Exception as exc:
        safe_log(f"failed-mail log error: {exc}")


def actor_label(auth):
    if not auth:
        return "system"
    if auth.get("role") == "admin":
        return "admin"
    if auth.get("role") == "root":
        return "root:" + str(auth.get("domain") or "")
    return "tenant:" + str(auth.get("domain") or "")


def domain_input(value, default=DOMAIN):
    default_domain = _clean_domain_value(default) or DOMAIN
    domain = _clean_domain_value(value or default_domain)
    if not domain:
        domain = default_domain
    if "." not in domain:
        root = root_domain_for(default_domain) or DOMAIN
        domain = f"{domain}.{root}"
    if not domain_format_valid(domain):
        raise ValueError("domain format invalid")
    return domain


def save_domain(value, note="", default=DOMAIN):
    domain = domain_input(value, default)
    now = now_ms()
    with db() as con:
        con.execute(
            "INSERT INTO mail_domains (domain,note,token,created_at) VALUES (?,?,?,?) ON CONFLICT(domain) DO UPDATE SET note=excluded.note",
            (domain, str(note or "")[:300], "", now),
        )
    invalidate_domain_cache()
    return domain


def public_http_url_ok(value, resolve=True):
    url = str(value or "").strip()
    if not url:
        return True, ""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "webhook URL invalid"
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False, "webhook URL must be http(s)"
    if parsed.username or parsed.password:
        return False, "webhook URL cannot contain credentials"
    host = parsed.hostname.strip().lower()
    if host in {"localhost", "localhost.localdomain"}:
        return False, "webhook URL cannot target localhost"
    if not resolve:
        return True, ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:
        return False, "webhook host cannot be resolved"
    checked = set()
    for info in infos:
        ip = info[4][0]
        if ip in checked:
            continue
        checked.add(ip)
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False, "webhook host resolved to an invalid address"
        if not addr.is_global:
            return False, "webhook URL cannot target private, local, reserved, or metadata networks"
    return True, ""


def update_domain_settings(domain, values):
    domain = normalize_domain(domain)
    int_fields = {
        "enabled": (0, 1),
        "token_disabled": (0, 1),
        "retention_hours": (1, 8760),
        "cleanup_max_mails": (0, 1000000),
        "alias_limit": (1, 1000000),
        "mail_limit": (1, 1000000),
        "storage_limit_mb": (16, 102400),
        "webhook_enabled": (0, 1),
    }
    text_fields = {
        "note": 300,
        "owner": 120,
        "brand_title": 120,
        "brand_desc": 300,
        "default_alias": 64,
        "theme_color": 24,
        "webhook_url": 500,
    }
    sets = []
    params = []
    for key, (low, high) in int_fields.items():
        if key in values:
            try:
                v = int(values.get(key))
            except Exception:
                v = low
            sets.append(f"{key}=?")
            params.append(max(low, min(v, high)))
    for key, max_len in text_fields.items():
        if key in values:
            v = str(values.get(key) or "").strip()
            if key == "default_alias":
                v = re.sub(r"[^a-z0-9._+-]", "", v.lower())[:64]
            if key == "theme_color" and v and not re.match(r"^#[0-9a-f]{6}$", v, re.I):
                v = ""
            if key == "webhook_url" and v:
                ok, reason = public_http_url_ok(v)
                if not ok:
                    raise ValueError(reason)
            sets.append(f"{key}=?")
            params.append(v[:max_len])
    if not sets:
        return domain_config(domain)
    with db() as con:
        con.execute(f"UPDATE mail_domains SET {', '.join(sets)} WHERE domain=?", params + [domain])
    return domain_config(domain)


def get_domain_by_token(token):
    token = str(token or "").strip()
    if not token or len(token) > 256:
        return ""
    with db() as con:
        row = con.execute("SELECT domain,enabled,token_disabled FROM mail_domains WHERE token=?", (token,)).fetchone()
    if row and (not int(row["enabled"] or 0) or int(row["token_disabled"] or 0)):
        return ""
    return row["domain"] if row else ""


def set_domain_token(domain, token=""):
    domain = normalize_domain(domain)
    token = str(token or "").strip() or ("domain_" + secrets.token_urlsafe(32))
    if len(token) > 256 or len(token) < 24:
        raise ValueError("token must be 24-256 characters")
    with db() as con:
        con.execute("UPDATE mail_domains SET token=? WHERE domain=?", (token, domain))
    return token


def normalize_domain(value, default=DOMAIN):
    domain = domain_input(value, default)
    if domain not in list_domains():
        raise ValueError("unsupported mail domain")
    return domain


def alias_count(domain):
    domain = normalize_domain(domain)
    with db() as con:
        row = con.execute("SELECT alias_count FROM domain_usage WHERE domain=?", (domain,)).fetchone()
    return int(row["alias_count"] or 0) if row else 0


def mail_usage(domain):
    domain = normalize_domain(domain)
    with db() as con:
        row = con.execute("SELECT mail_count,storage_bytes FROM domain_usage WHERE domain=?", (domain,)).fetchone()
    return (int(row["mail_count"] or 0), int(row["storage_bytes"] or 0)) if row else (0, 0)


def allowed_mailbox(email, for_receipt=False):
    em = normalize_addr(email)
    domain = domain_of_email(em)
    if not domain:
        return False
    cfg = domain_config(domain)
    if not int(cfg.get("enabled") or 0):
        return False
    if not for_receipt:
        return True
    with db() as con:
        local_exists = bool(con.execute("SELECT 1 FROM aliases WHERE email=?", (em,)).fetchone())
        usage = con.execute("SELECT mail_count,storage_bytes,alias_count FROM domain_usage WHERE domain=?", (domain,)).fetchone()
    mail_count = int(usage["mail_count"] or 0) if usage else 0
    storage_bytes = int(usage["storage_bytes"] or 0) if usage else 0
    aliases = int(usage["alias_count"] or 0) if usage else 0
    if not local_exists and aliases >= int(cfg.get("alias_limit") or DEFAULT_ALIAS_LIMIT):
        return False
    if mail_count >= int(cfg.get("mail_limit") or DEFAULT_MAIL_LIMIT):
        return False
    if storage_bytes >= int(cfg.get("storage_limit_mb") or DEFAULT_STORAGE_LIMIT_MB) * 1024 * 1024:
        return False
    return True


def alias_email(value, domain=DOMAIN):
    domain = normalize_domain(domain)
    value = str(value or "").lower().strip()
    if "@" in value:
        em = normalize_addr(value)
        if allowed_mailbox(em):
            return em
        raise ValueError("alias must end with one of: " + ", ".join("@" + d for d in list_domains()))
    if not re.match(r"^[a-z0-9._+-]{1,64}$", value, re.I):
        raise ValueError("alias prefix invalid")
    return f"{value}@{domain}"


def save_alias(email, note="", domain=DOMAIN):
    em = alias_email(email, domain)
    target_domain = domain_of_email(em)
    if not target_domain:
        raise ValueError("unsupported mail domain")
    cfg = domain_config(target_domain)
    if not int(cfg.get("enabled") or 0):
        raise ValueError("domain disabled")
    now = int(time.time() * 1000)
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        exists = con.execute("SELECT 1 FROM aliases WHERE email=?", (em,)).fetchone()
        usage = con.execute("SELECT alias_count FROM domain_usage WHERE domain=?", (target_domain,)).fetchone()
        current = int(usage["alias_count"] or 0) if usage else 0
        if not exists and current >= int(cfg.get("alias_limit") or DEFAULT_ALIAS_LIMIT):
            raise ValueError("alias limit reached")
        con.execute(
            "INSERT INTO aliases (email,domain,note,created_at) VALUES (?,?,?,?) ON CONFLICT(email) DO UPDATE SET note=excluded.note, domain=excluded.domain",
            (em, target_domain, str(note or "")[:300], now),
        )
    return em


_CODE_STRONG_KEYWORD_RE = re.compile(
    r"(?:验证码|驗證碼|校验码|校驗碼|动态码|動態碼|安全码|安全碼|临时验证码|一次性(?:代码|密码|密碼)|"
    r"认证码|認證碼|授权码|授權碼|确认码|確認碼|激活码|啟用碼|启用码|登录码|登入碼|取件码|"
    r"認証コード|確認コード|ワンタイムパスワード|인증\s*(?:코드|번호)|확인\s*코드|"
    r"verification\s+code|confirmation\s+code|security\s+code|one[-\s]?time\s+(?:code|password|passcode)|"
    r"temporary\s+code|login\s+code|sign[-\s]?in\s+code|auth(?:entication)?\s+code|activation\s+code|"
    r"email\s+code|magic\s+code|c[oó]digo\s+de\s+(?:verificaci[oó]n|verifica[cç][aã]o|seguran[cç]a)|"
    r"code\s+de\s+v[ée]rification|best[äa]tigungscode|sicherheitscode|codice\s+di\s+verifica|"
    r"код\s+(?:подтверждения|безопасности|проверки)|проверочный\s+код|одноразовый\s+код|"
    r"رمز\s+(?:التحقق|التأكيد|الأمان)|كلمة\s+مرور\s+لمرة\s+واحدة|"
    r"verificatiecode|kod\s+weryfikacyjny|doğrulama\s+kodu|kode\s+verifikasi|mã\s+xác\s+minh|सत्यापन\s+कोड)",
    re.I,
)
_CODE_GENERIC_KEYWORD_RE = re.compile(r"(?<![a-z0-9])(?:code|passcode|pin|otp|totp|mfa|2fa|口令|代码)(?![a-z0-9])", re.I)
_CODE_NEGATIVE_RE = re.compile(
    r"(?:订单|訂單|物流|运单|運單|发票|發票|金额|金額|电话|電話|邮编|郵編|编号|編號|账号|帳號|"
    r"order|invoice|receipt|amount|price|total|phone|tel|zip|postal|tracking|shipment|ticket|case|account|user\s*id)",
    re.I,
)
_CODE_NEGATED_CONTEXT_RE = re.compile(
    r"(?:\b(?:no|not|without)\s+(?:a\s+)?(?:verification\s+|confirmation\s+|security\s+|one[-\s]?time\s+)?"
    r"(?:code|passcode|pin|otp)(?:\s+is)?\s+(?:required|needed|necessary|requested|used)\b|"
    r"\b(?:verification\s+code|confirmation\s+code|security\s+code|passcode|pin|otp)\s+is\s+not\s+"
    r"(?:required|needed|necessary|requested|used)\b|"
    r"\bdo\s+not\s+need\s+(?:a\s+)?(?:verification\s+|confirmation\s+|security\s+)?(?:code|passcode|pin|otp)\b|"
    r"(?:无需|不需要|不用|未要求).{0,10}(?:验证码|驗證碼|校验码|安全码|动态码|認證碼|认证码|口令|代码)|"
    r"(?:验证码|驗證碼|校验码|安全码|动态码|認證碼|认证码|口令|代码).{0,10}(?:无需|不需要|不用|未要求))",
    re.I,
)
_CODE_CANDIDATE_PATTERNS = (
    re.compile(r"(?<![A-Z0-9])([A-Z0-9]{1,6}(?:[-_.][A-Z0-9]{1,6}){1,3})(?![A-Z0-9])", re.I),
    re.compile(r"(?<![A-Z0-9])([A-Z0-9](?:[ \t\u00a0]+[A-Z0-9]){3,11})(?![A-Z0-9])", re.I),
    re.compile(r"(?<!\d)(\d{2,4}(?:[ \t\u00a0-]+\d{2,4}){1,3})(?!\d)"),
    re.compile(r"(?<![A-Z0-9])([A-Z0-9]{4,12})(?![A-Z0-9])", re.I),
)
_CODE_STOP_WORDS = {
    "CODE", "PIN", "OTP", "TOTP", "MFA", "LOGIN", "EMAIL", "MAIL", "USER", "ACCOUNT", "PASSWORD",
    "PASSCODE", "MAGIC", "SIGNIN", "SIGN", "ACTIVATION", "VERIFY", "VERIFICATION", "CONFIRM", "CONFIRMATION",
    "SECURITY", "AUTH", "AUTHENTICATION", "YOUR", "THIS", "THAT", "WITH", "ENTER", "INPUT", "PLEASE", "CONTINUE",
    "EXPIRES", "MINUTES", "NEVER", "SHARE", "DEVICE", "ACCESS", "WELCOME", "SERVICE", "SUPPORT", "GITHUB",
    "REQUIRED", "REQUIRE", "NEEDED", "NECESSARY", "REQUESTED", "SHIPPED",
}


def _clean_code_source(value):
    value = unicodedata.normalize("NFKC", html.unescape(str(value or "")))
    value = "".join(str(unicodedata.decimal(char)) if char.isdecimal() else char for char in value)
    value = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", value)
    value = re.sub(r"https?://[^\s<>\"']+", " ", value, flags=re.I)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.\w+\b", " ", value)
    return value


def _normalized_code(value):
    return re.sub(r"[\s\-_.·•]+", "", str(value or "")).upper()


def _nearest_match_distance(matches, start, end):
    if not matches:
        return 100000
    return min(0 if m.start() <= end and m.end() >= start else min(abs(start - m.end()), abs(m.start() - end)) for m in matches)


def _valid_code_candidate(raw, keyword_distance):
    code = _normalized_code(raw)
    if not re.fullmatch(r"[A-Z0-9]{4,12}", code, re.I) or code in _CODE_STOP_WORDS:
        return ""
    if len(set(code)) == 1 or re.fullmatch(r"(?:19|20)\d{2}", code):
        return ""
    if re.fullmatch(r"\d{8}", code):
        try:
            time.strptime(code, "%Y%m%d")
            return ""
        except ValueError:
            pass
    if code.isdigit():
        return code if len(code) in (4, 5, 6, 7, 8) else ""
    has_digit = bool(re.search(r"\d", code))
    if not has_digit and (keyword_distance > 40 or not 5 <= len(code) <= 10):
        return ""
    return code


def extract_code(subject, text):
    subject_source = _clean_code_source(subject)
    body_source = _clean_code_source(text)
    source = (subject_source + "\n" + body_source)[:50000]
    if not source.strip():
        return ""

    subject_end = len(subject_source)
    negated_spans = [match.span() for match in _CODE_NEGATED_CONTEXT_RE.finditer(source)]

    def active_keyword(match):
        return not any(start <= match.start() and match.end() <= end for start, end in negated_spans)

    strong_matches = [match for match in _CODE_STRONG_KEYWORD_RE.finditer(source) if active_keyword(match)]
    generic_matches = [match for match in _CODE_GENERIC_KEYWORD_RE.finditer(source) if active_keyword(match)]
    negative_matches = list(_CODE_NEGATIVE_RE.finditer(source))
    candidates = []
    seen = set()

    for pattern in _CODE_CANDIDATE_PATTERNS:
        for match in pattern.finditer(source):
            raw = match.group(1)
            start, end = match.span(1)
            strong_distance = _nearest_match_distance(strong_matches, start, end)
            generic_distance = _nearest_match_distance(generic_matches, start, end)
            code = _valid_code_candidate(raw, min(strong_distance, generic_distance))
            key = (start, code)
            if not code or key in seen:
                continue
            seen.add(key)

            negative_distance = _nearest_match_distance(negative_matches, start, end)
            score = 10
            if strong_distance <= 120:
                score += max(55, 150 - strong_distance)
            elif generic_distance <= 70:
                score += max(40, 105 - generic_distance)
            if negative_distance <= 80 and negative_distance <= min(strong_distance, generic_distance):
                score -= max(45, 135 - negative_distance)
            if start <= subject_end:
                score += 20
            if code.isdigit() and len(code) == 6:
                score += 30
            elif code.isdigit():
                score += 18
            elif re.search(r"\d", code):
                score += 24
            else:
                score -= 15
            if re.search(r"[\s\-_.]", raw):
                score += 12
            line_start = source.rfind("\n", 0, start) + 1
            line_end = source.find("\n", end)
            if line_end < 0:
                line_end = len(source)
            if _normalized_code(source[line_start:line_end].strip(" \t:：=()[]{}<>")) == code:
                score += 55
            if re.search(r"[:：=]\s*$", source[max(0, start - 12):start]):
                score += 16
            if start < 1500:
                score += 5
            candidates.append((score, start, code))

    if not candidates:
        return ""
    candidates.sort(key=lambda item: (-item[0], item[1], -len(item[2])))
    return candidates[0][2] if candidates[0][0] >= 80 else ""

def decode_value(value):
    try:
        return str(make_header(decode_header(value or "")))
    except Exception:
        return str(value or "")

def strip_html(value):
    s = value or ""
    links = []

    def anchor_repl(match):
        attrs = match.group(1) or ""
        label = strip_html(match.group(2) or "")
        href_match = re.search(r'''href=["\']([^"\']+)["\']''', attrs, re.I)
        href = html.unescape(href_match.group(1).strip()) if href_match else ""
        if href and href.startswith(("http://", "https://")):
            links.append(href)
            return f" {label or '链接'} {href} "
        return f" {label} "

    s = re.sub(r"(?is)<a\b([^>]*)>(.*?)</a>", anchor_repl, s)
    links.extend(re.findall(r"https?://[^\s<>'\"]+", s))
    s = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", s)
    s = re.sub(r"(?is)<br\s*/?>", "\n", s)
    s = re.sub(r"(?is)</(?:p|div|section|article|header|footer|main|aside|li|tr|h[1-6])\s*>", "\n", s)
    s = re.sub(r"(?is)<(?:p|div|section|article|header|footer|main|aside|li|tr|h[1-6])\b[^>]*>", "\n", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"[^\S\r\n]+", " ", s)
    s = re.sub(r" *\n *", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s).strip()

    seen = set()
    clean_links = []
    for link in links:
        link = html.unescape(link).strip().rstrip(').,;')
        if link and link not in seen:
            seen.add(link)
            clean_links.append(link)
    if clean_links:
        s = (s + "\n\n链接:\n" + "\n".join(clean_links)).strip()
    return s
def payload_text(msg):
    parts = []
    html_parts = []
    if msg.is_multipart():
        walk = msg.walk()
    else:
        walk = [msg]
    for part in walk:
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        disp = (part.get_content_disposition() or "").lower()
        if disp == "attachment":
            continue
        try:
            content = part.get_content()
        except Exception:
            try:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                content = payload.decode(charset, errors="replace")
            except Exception:
                content = ""
        if ctype == "text/plain" and content:
            parts.append(str(content))
        elif ctype == "text/html" and content:
            html_parts.append(strip_html(str(content)))
    text = "\n".join(p.strip() for p in parts if p and p.strip())
    html_text = "\n".join(p for p in html_parts if p)
    html_links = []
    for link in re.findall(r"https?://[^\s<>'\"]+", html_text):
        link = link.strip().rstrip(').,;')
        if link and link not in html_links:
            html_links.append(link)
    if text and html_links:
        existing = set(re.findall(r"https?://[^\s<>'\"]+", text))
        extra = [link for link in html_links if link not in existing]
        if extra:
            text = text + "\n\n链接:\n" + "\n".join(extra)
    if not text:
        text = html_text
    return text[:MAX_TEXT_CHARS]


def extract_attachments_from_msg(msg):
    items = []
    walk = msg.walk() if msg.is_multipart() else [msg]
    for part in walk:
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disp != "attachment" and not filename:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        if not payload:
            continue
        items.append({
            "filename": decode_value(filename or "attachment"),
            "content_type": part.get_content_type() or "application/octet-stream",
            "size": len(payload),
            "data": payload if len(payload) <= MAX_ATTACHMENT_BYTES else None,
        })
    return items


def notify_webhook(domain, payload):
    try:
        cfg = domain_config(domain)
        if not int(cfg.get("webhook_enabled") or 0):
            return
        url = (cfg.get("webhook_url") or "").strip()
        ok, reason = public_http_url_ok(url)
        if not ok:
            log_failed_mail(payload.get("fromEmail", ""), payload.get("toEmail", ""), "webhook blocked", reason)
            return
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urlrequest.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        class _NoRedirect(urlrequest.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urlrequest.build_opener(_NoRedirect)
        with opener.open(req, timeout=5) as resp:
            resp.read(128)
    except Exception as exc:
        log_failed_mail(payload.get("fromEmail", ""), payload.get("toEmail", ""), "webhook failed", str(exc))


def notify_webhook_async(domain, payload):
    if not _WEBHOOK_SLOTS.acquire(blocking=False):
        safe_log(f"webhook queue full domain={domain}")
        return
    try:
        future = _WEBHOOK_EXECUTOR.submit(notify_webhook, domain, dict(payload or {}))
        future.add_done_callback(lambda _future: _WEBHOOK_SLOTS.release())
    except RuntimeError:
        _WEBHOOK_SLOTS.release()
        safe_log("webhook executor is unavailable")


def cleanup_domain(domain, reason="retention"):
    domain = normalize_domain(domain)
    cfg = domain_config(domain)
    deleted = 0
    now = int(time.time() * 1000)
    with db() as con:
        retention_hours = int(cfg.get("retention_hours") or RETENTION_HOURS)
        if retention_hours > 0:
            cutoff = int((time.time() - retention_hours * 3600) * 1000)
            cur = con.execute("DELETE FROM mails WHERE domain=? AND received_at < ?", (domain, cutoff))
            deleted += cur.rowcount
        max_mails = int(cfg.get("cleanup_max_mails") or 0)
        if max_mails > 0:
            cur = con.execute(
                """
                DELETE FROM mails
                WHERE domain=?
                  AND id NOT IN (
                    SELECT id FROM mails
                    WHERE domain=?
                    ORDER BY pinned DESC, starred DESC, received_at DESC
                    LIMIT ?
                  )
                """,
                (domain, domain, max_mails),
            )
            deleted += cur.rowcount
        if deleted:
            con.execute("DELETE FROM attachments WHERE mail_id NOT IN (SELECT id FROM mails)")
            con.execute(
                "INSERT INTO cleanup_runs (domain,deleted_count,reason,created_at) VALUES (?,?,?,?)",
                (domain, deleted, reason, now),
            )
    return deleted


def store_mails(mail_from, rcpt_to_list, raw_bytes):
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise ValueError("raw message must be bytes")
    if len(raw_bytes) > MAX_MESSAGE_BYTES:
        raise ValueError("message too large")
    recipients = []
    for value in rcpt_to_list or []:
        email = normalize_addr(value)
        if not email or email in recipients:
            continue
        recipients.append(email)
    if not recipients:
        raise ValueError("recipient required")
    from_email = normalize_addr(mail_from)
    recipient_domains = {}
    configs = {}
    for to_email in recipients:
        domain = domain_of_email(to_email)
        if not domain:
            raise ValueError("unsupported mail domain")
        cfg = configs.setdefault(domain, domain_config(domain))
        if not int(cfg.get("enabled") or 0):
            raise ValueError("domain disabled")
        recipient_domains[to_email] = domain

    msg = BytesParser(policy=policy.default).parsebytes(bytes(raw_bytes))
    subject = decode_value(msg.get("subject", ""))[:500]
    text = payload_text(msg)
    raw = bytes(raw_bytes).decode("utf-8", errors="replace")[:1200000]
    now = int(time.time() * 1000)
    attachments = extract_attachments_from_msg(msg)
    verification_code = extract_code(subject, text)
    has_link = 1 if message_has_link(text, raw) else 0
    stored_bytes = stored_message_bytes(text, raw, attachments)
    grouped = {}
    for to_email, domain in recipient_domains.items():
        grouped.setdefault(domain, []).append(to_email)
    usage_before = {}
    stored = []
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        for domain, domain_recipients in grouped.items():
            cfg = configs[domain]
            usage = con.execute(
                "SELECT mail_count,storage_bytes,alias_count FROM domain_usage WHERE domain=?",
                (domain,),
            ).fetchone()
            mail_count = int(_row_get(usage, "mail_count", 0) or 0)
            storage_used = int(_row_get(usage, "storage_bytes", 0) or 0)
            aliases_used = int(_row_get(usage, "alias_count", 0) or 0)
            placeholders = ",".join("?" for _ in domain_recipients)
            existing = con.execute(
                f"SELECT COUNT(*) AS c FROM aliases WHERE domain=? AND email IN ({placeholders})",
                [domain] + domain_recipients,
            ).fetchone()
            new_aliases = len(domain_recipients) - int(existing["c"] or 0)
            if aliases_used + new_aliases > int(cfg.get("alias_limit") or DEFAULT_ALIAS_LIMIT):
                raise ValueError("alias limit reached")
            if mail_count + len(domain_recipients) > int(cfg.get("mail_limit") or DEFAULT_MAIL_LIMIT):
                raise ValueError("mail limit reached")
            if storage_used + stored_bytes * len(domain_recipients) > int(cfg.get("storage_limit_mb") or DEFAULT_STORAGE_LIMIT_MB) * 1024 * 1024:
                raise ValueError("storage limit reached")
            usage_before[domain] = mail_count

        for to_email in recipients:
            domain = recipient_domains[to_email]
            con.execute(
                "INSERT INTO aliases (email,domain,note,created_at) VALUES (?,?,?,?) ON CONFLICT(email) DO UPDATE SET domain=excluded.domain",
                (to_email, domain, "auto", now),
            )
            cur = con.execute(
                "INSERT INTO mails (to_email,domain,from_email,subject,text,raw,received_at,verification_code,has_link,metadata_version,stored_bytes) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (to_email, domain, from_email, subject, text, raw, now, verification_code, has_link, MAIL_METADATA_VERSION, stored_bytes),
            )
            mail_id = cur.lastrowid
            for item in attachments:
                con.execute(
                    "INSERT INTO attachments (mail_id,filename,content_type,size,data,created_at) VALUES (?,?,?,?,?,?)",
                    (
                        mail_id,
                        str(item["filename"] or "attachment")[:260],
                        str(item["content_type"] or "application/octet-stream")[:160],
                        int(item["size"] or 0),
                        item["data"],
                        now,
                    ),
                )
            stored.append({"id": mail_id, "to": to_email, "domain": domain})
    signal_mail_change()
    for item in stored:
        safe_log(f"stored mail id={item['id']} domain={item['domain']} bytes={stored_bytes}")
        notify_webhook_async(item["domain"], {
            "event": "mail.received",
            "domain": item["domain"],
            "id": item["id"],
            "toEmail": item["to"],
            "fromEmail": from_email,
            "subject": subject,
            "code": verification_code,
            "receivedAt": now,
        })
    for domain, domain_recipients in grouped.items():
        try:
            cleanup_limit = int(configs[domain].get("cleanup_max_mails") or 0)
            cleanup_domain_if_due(
                domain,
                force=bool(cleanup_limit and usage_before.get(domain, 0) + len(domain_recipients) > cleanup_limit),
            )
        except Exception as exc:
            safe_log(f"post-receive cleanup domain={domain} error: {exc}")
    return [item["id"] for item in stored]


def store_mail(mail_from, rcpt_to, raw_bytes):
    return store_mails(mail_from, [rcpt_to], raw_bytes)[0]



def _message_from_raw(raw):
    return BytesParser(policy=policy.default).parsebytes((raw or "").encode("utf-8", errors="replace"))


def _safe_html(value):
    s = str(value or "")
    if not s.strip():
        return ""
    s = re.sub(r"(?is)<base\b[^>]*>", "", s)
    s = re.sub(r"(?is)<script\b.*?>.*?</script>", "", s)
    s = re.sub(r"(?is)<style\b.*?>.*?</style>", "", s)
    s = re.sub(r"(?is)<iframe\b.*?>.*?</iframe>", "", s)
    s = re.sub(r"(?is)<object\b.*?>.*?</object>", "", s)
    s = re.sub(r"(?is)<embed\b.*?>.*?</embed>", "", s)
    s = re.sub(r"(?is)<form\b.*?>.*?</form>", "", s)
    s = re.sub(r"(?is)<link\b[^>]*>", "", s)
    s = re.sub(r"(?is)<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>", "", s)
    s = re.sub(r"(?is)<img\b[^>]*>", "", s)
    s = re.sub(r"\s+on[a-zA-Z]+\s*=\s*(['\"]).*?\1", "", s)
    s = re.sub(r"\s+on[a-zA-Z]+\s*=\s*[^\s>]+", "", s)
    s = re.sub(r"\s+(href|src|xlink:href)\s*=\s*(['\"])\s*(?:javascript|vbscript|data:|file:|ftp:)[^'\"]*\2", "", s, flags=re.I)
    s = re.sub(r"\s+(href|src|xlink:href)\s*=\s*(?:javascript|vbscript|data:|file:|ftp:)[^\s>]*", "", s, flags=re.I)
    s = re.sub(r"\s+target\s*=\s*(['\"]?)_parent\1", "", s, flags=re.I)
    s = re.sub(r"\s+target\s*=\s*(['\"]?)_top\1", "", s, flags=re.I)
    s = re.sub(r"\s+style\s*=\s*(['\"]).*?(?:expression\s*\(|javascript:|url\s*\().*?\1", "", s, flags=re.I | re.S)
    s = re.sub(r"(?i)<a\b", '<a rel="noopener noreferrer"', s)
    s = re.sub(r"(?i)<head([^>]*)>", '<head\\1><base target="_blank">', s, count=1)
    if "<base" not in s.lower():
        s = '<base target="_blank">' + s
    return s


def _html_and_links_from_raw(raw, fallback_text=""):
    msg = _message_from_raw(raw)
    html_parts = []
    text_parts = []
    walk = msg.walk() if msg.is_multipart() else [msg]
    for part in walk:
        if part.is_multipart() or (part.get_content_disposition() or "").lower() == "attachment":
            continue
        ctype = (part.get_content_type() or "").lower()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="replace")
        if ctype == "text/html" and body:
            html_parts.append(str(body))
        elif ctype == "text/plain" and body:
            text_parts.append(str(body))
    html_body = "\n".join(html_parts)
    links = []
    seen = set()
    blocked = ("/track/open", "/wf/open", ".woff", ".png", ".jpg", ".gif", ".svg", ".css", "help.openai.com", "unsubscribe", "privacy", "terms")
    action = ("accept-invite", "invite", "verify", "confirm", "activate", "authorize", "login", "magic", "reset", "continue", "redeem")
    cn_action = ("开始", "接受", "验证", "确认", "登录", "继续", "加入", "重置")
    for m in re.finditer(r"(?is)<a\b([^>]*)>(.*?)</a>", html_body):
        attrs = m.group(1) or ""
        label = strip_html(m.group(2) or "") or "打开链接"
        hm = re.search(r"href\s*=\s*([\"'])(.*?)\1", attrs, re.I | re.S)
        if not hm:
            continue
        url = html.unescape(hm.group(2).strip())
        low = url.lower()
        label_low = label.lower()
        if url.startswith(("http://", "https://")) and not any(x in low for x in blocked) and (any(x in low for x in action) or any(x in label_low for x in action) or any(x in label for x in cn_action)) and url not in seen:
            seen.add(url)
            links.append({"label": label[:80], "url": url})
    text_source = "\n".join(text_parts).strip() or fallback_text or ""
    for url in re.findall(r"https?://[^\s<>'\"]+", text_source):
        url = html.unescape(url).strip().rstrip(').,;')
        low = url.lower()
        if url.startswith(("http://", "https://")) and not any(x in low for x in blocked) and url not in seen:
            seen.add(url)
            links.append({"label": "打开链接", "url": url})
    if not html_body:
        text = text_source
        html_body = "<pre style='white-space:pre-wrap;font:14px/1.55 system-ui'>" + html.escape(text) + "</pre>"
    return _safe_html(html_body), links[:5]

def cleanup_old():
    total = 0
    for domain in list_domains():
        try:
            total += cleanup_domain(domain, "scheduled")
        except Exception as exc:
            safe_log(f"cleanup domain={domain} error: {exc}")
    return total


def delete_mail(message_id, allowed_domain=""):
    message_id = int(message_id or 0)
    if message_id <= 0:
        raise ValueError("message id required")
    with db() as con:
        row = con.execute("SELECT id,to_email,domain FROM mails WHERE id=?", (message_id,)).fetchone()
        if not row:
            return False
        row_domain = row["domain"] or domain_of_email(row["to_email"])
        if not scope_allows_domain(allowed_domain, row_domain):
            raise PermissionError("cannot delete this message")
        con.execute("DELETE FROM attachments WHERE mail_id=?", (message_id,))
        con.execute("DELETE FROM mails WHERE id=?", (message_id,))
    return True


def clear_domain_mails(domain, allowed_domain=""):
    domain = normalize_domain(domain)
    if not scope_allows_domain(allowed_domain, domain):
        raise PermissionError("cannot clear this domain")
    with db() as con:
        rows = con.execute("SELECT id FROM mails WHERE domain=?", (domain,)).fetchall()
        ids = [r["id"] for r in rows]
        for i in range(0, len(ids), 800):
            chunk = ids[i:i + 800]
            if chunk:
                con.execute("DELETE FROM attachments WHERE mail_id IN (%s)" % ",".join("?" for _ in chunk), chunk)
        cur = con.execute("DELETE FROM mails WHERE domain=?", (domain,))
    return cur.rowcount


def clear_alias_mails(email, allowed_domain=""):
    em = normalize_addr(email)
    domain = domain_of_email(em)
    if not domain:
        raise ValueError("unsupported mail domain")
    if not scope_allows_domain(allowed_domain, domain):
        raise PermissionError("cannot clear this mailbox")
    with db() as con:
        rows = con.execute("SELECT id FROM mails WHERE to_email=?", (em,)).fetchall()
        ids = [r["id"] for r in rows]
        for i in range(0, len(ids), 800):
            chunk = ids[i:i + 800]
            if chunk:
                con.execute("DELETE FROM attachments WHERE mail_id IN (%s)" % ",".join("?" for _ in chunk), chunk)
        cur = con.execute("DELETE FROM mails WHERE to_email=?", (em,))
    return cur.rowcount


def _row_get(row, key, default=None):
    try:
        if isinstance(row, dict):
            return row.get(key, default)
        return row[key] if key in row.keys() else default
    except (KeyError, TypeError, AttributeError):
        return default


def mail_row_json(row, include_body=True):
    text = _row_get(row, "text", "") or ""
    raw = _row_get(row, "raw", "") or ""
    stored_code = _row_get(row, "verification_code", None)
    stored_has_link = _row_get(row, "has_link", None)
    return {
        "id": _row_get(row, "id", 0),
        "to": _row_get(row, "to_email", "") or "",
        "toEmail": _row_get(row, "to_email", "") or "",
        "from": _row_get(row, "from_email", "") or "",
        "fromEmail": _row_get(row, "from_email", "") or "",
        "subject": _row_get(row, "subject", "") or "",
        "text": text if include_body else text[:300],
        "content": text if include_body else text[:300],
        "receivedAt": _row_get(row, "received_at", 0),
        "isRead": bool(_row_get(row, "is_read", 0)),
        "readAt": _row_get(row, "read_at", None),
        "starred": bool(_row_get(row, "starred", 0)),
        "pinned": bool(_row_get(row, "pinned", 0)),
        "hasLink": bool(stored_has_link) if stored_has_link is not None else message_has_link(text, raw),
        "code": str(stored_code or "") if stored_code is not None else extract_code(_row_get(row, "subject", "") or "", text),
    }


def latest_mail_snapshot(domain, email=""):
    domain = normalize_domain(domain)
    email = normalize_addr(email)
    with db() as con:
        if email:
            stats = con.execute("SELECT mail_count AS c,latest_mail_at AS latest FROM aliases WHERE email=?", (email,)).fetchone()
            if not stats:
                stats = con.execute(
                    "SELECT COUNT(*) AS c, COALESCE(MAX(received_at),0) AS latest FROM mails WHERE to_email=?",
                    (email,),
                ).fetchone()
            row = con.execute(
                "SELECT id,to_email,received_at FROM mails WHERE to_email=? ORDER BY received_at DESC,id DESC LIMIT 1",
                (email,),
            ).fetchone()
        else:
            stats = con.execute("SELECT mail_count AS c FROM domain_usage WHERE domain=?", (domain,)).fetchone()
            row = con.execute(
                "SELECT id,to_email,received_at FROM mails WHERE domain=? ORDER BY received_at DESC,id DESC LIMIT 1",
                (domain,),
            ).fetchone()
    latest = int(_row_get(stats, "latest", 0) or 0) if stats else 0
    if row:
        latest = max(latest, int(row["received_at"] or 0))
    return {
        "latest": latest,
        "count": int(stats["c"] or 0) if stats else 0,
        "latestId": int(row["id"]) if row else 0,
        "latestEmail": row["to_email"] if row else "",
        "latestReceivedAt": int(row["received_at"] or latest) if row else latest,
    }


def list_messages_page(domain, email="", query="", page=1, page_size=50, filters=None):
    domain = normalize_domain(domain)
    filters = filters or {}
    email = normalize_addr(email)
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or 50), 100))
    where = ["domain=?"]
    params = [domain]
    if email:
        if not email.endswith("@" + domain):
            raise ValueError("email domain mismatch")
        where = ["to_email=?"]
        params = [email]
    q = str(query or "").strip().lower()
    if q:
        like = "%" + q + "%"
        where.append("(LOWER(COALESCE(from_email,'')) LIKE ? OR LOWER(COALESCE(subject,'')) LIKE ? OR LOWER(COALESCE(to_email,'')) LIKE ? OR LOWER(COALESCE(text,'')) LIKE ?)")
        params.extend([like, like, like, like])
    field_map = {
        "from": "from_email",
        "subject": "subject",
        "to": "to_email",
    }
    for key, col in field_map.items():
        value = str(filters.get(key) or "").strip().lower()
        if value:
            where.append(f"LOWER(COALESCE({col},'')) LIKE ?")
            params.append("%" + value + "%")
    if filters.get("unread"):
        where.append("is_read=0")
    if filters.get("starred"):
        where.append("starred=1")
    if filters.get("pinned"):
        where.append("pinned=1")
    if filters.get("today"):
        lt = time.localtime()
        start = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, lt.tm_wday, lt.tm_yday, lt.tm_isdst)) * 1000)
        where.append("received_at>=?")
        params.append(start)
    if filters.get("dateFrom"):
        try:
            start = int(time.mktime(time.strptime(str(filters.get("dateFrom")), "%Y-%m-%d")) * 1000)
            where.append("received_at>=?")
            params.append(start)
        except Exception:
            pass
    if filters.get("dateTo"):
        try:
            end_tuple = time.strptime(str(filters.get("dateTo")), "%Y-%m-%d")
            end = int((time.mktime(end_tuple) + 86400) * 1000)
            where.append("received_at<?")
            params.append(end)
        except Exception:
            pass
    needs_code_filter = bool(filters.get("hasCode") or filters.get("code"))
    if needs_code_filter or filters.get("hasLink"):
        backfill_message_metadata(batch_size=500, max_batches=2, domain=domain)
    if filters.get("hasLink"):
        where.append("has_link=1")
    if filters.get("hasCode"):
        where.append("COALESCE(verification_code,'')<>''")
    code_q = _normalized_code(filters.get("code") or "")
    if code_q:
        where.append("UPPER(COALESCE(verification_code,'')) LIKE ?")
        params.append("%" + code_q + "%")
    where_sql = " AND ".join(where)
    list_columns = (
        "id,to_email,domain,from_email,subject,SUBSTR(COALESCE(text,''),1,300) AS text,received_at,"
        "is_read,read_at,starred,pinned,verification_code,has_link,metadata_version"
    )
    with db() as con:
        total = con.execute(f"SELECT COUNT(*) AS c FROM mails WHERE {where_sql}", params).fetchone()["c"]
        rows = con.execute(
            f"SELECT {list_columns} FROM mails WHERE {where_sql} ORDER BY pinned DESC, starred DESC, received_at DESC, id DESC LIMIT ? OFFSET ?",
            params + [page_size, (page - 1) * page_size],
        ).fetchall()
    return [mail_row_json(r, include_body=False) for r in rows], total, page, page_size


def message_ids_allowed(ids, allowed_domain=""):
    ids = [int(x) for x in ids if str(x).strip().isdigit()]
    ids = list(dict.fromkeys([x for x in ids if x > 0]))[:1000]
    if not ids:
        return []
    rows = []
    with db() as con:
        for i in range(0, len(ids), 800):
            chunk = ids[i:i + 800]
            rows.extend(con.execute(
                "SELECT id,to_email,domain FROM mails WHERE id IN (%s)" % ",".join("?" for _ in chunk),
                chunk,
            ).fetchall())
    allowed = []
    for row in rows:
        row_domain = row["domain"] or domain_of_email(row["to_email"])
        if not scope_allows_domain(allowed_domain, row_domain):
            raise PermissionError("cannot access messages outside this domain")
        allowed.append(row["id"])
    return allowed


def set_messages_state(ids, values, allowed_domain=""):
    allowed = message_ids_allowed(ids, allowed_domain)
    if not allowed:
        return 0
    sets = []
    params = []
    now = int(time.time() * 1000)
    for key, col in (("isRead", "is_read"), ("starred", "starred"), ("pinned", "pinned")):
        if key in values:
            sets.append(f"{col}=?")
            params.append(1 if values.get(key) else 0)
            if key == "isRead":
                sets.append("read_at=?")
                params.append(now if values.get(key) else None)
    if not sets:
        return 0
    sets.append("updated_at=?")
    params.append(now)
    total = 0
    with db() as con:
        for i in range(0, len(allowed), 800):
            chunk = allowed[i:i + 800]
            cur = con.execute(
                f"UPDATE mails SET {', '.join(sets)} WHERE id IN ({','.join('?' for _ in chunk)})",
                params + chunk,
            )
            total += cur.rowcount
    return total


def bulk_delete_messages(ids, allowed_domain=""):
    allowed = message_ids_allowed(ids, allowed_domain)
    total = 0
    with db() as con:
        for i in range(0, len(allowed), 800):
            chunk = allowed[i:i + 800]
            if not chunk:
                continue
            con.execute("DELETE FROM attachments WHERE mail_id IN (%s)" % ",".join("?" for _ in chunk), chunk)
            cur = con.execute("DELETE FROM mails WHERE id IN (%s)" % ",".join("?" for _ in chunk), chunk)
            total += cur.rowcount
    return total


def message_attachments(mail_id):
    with db() as con:
        rows = con.execute("SELECT id,filename,content_type,size,data IS NOT NULL AS downloadable FROM attachments WHERE mail_id=? ORDER BY id", (int(mail_id),)).fetchall()
    return [dict(id=r["id"], filename=r["filename"] or "attachment", contentType=r["content_type"] or "application/octet-stream", size=r["size"], downloadable=bool(r["downloadable"])) for r in rows]


def message_headers(raw):
    try:
        msg = _message_from_raw(raw)
        return [{"name": k, "value": decode_value(v)} for k, v in msg.items()]
    except Exception:
        return []


def db_file_size():
    total = 0
    for suffix in ("", "-wal", "-shm"):
        p = DB_PATH + suffix
        if os.path.exists(p):
            total += os.path.getsize(p)
    return total


def backup_total_size():
    total = 0
    for p in Path(BACKUP_DIR).glob("*.sqlite3"):
        try:
            total += p.stat().st_size
        except OSError:
            pass
    return total


def prune_backups():
    files = []
    for p in Path(BACKUP_DIR).glob("*.sqlite3"):
        try:
            files.append((p.stat().st_mtime, p.stat().st_size, p))
        except OSError:
            pass
    files.sort(key=lambda item: item[0], reverse=True)
    total = sum(size for _, size, _ in files)
    kept = list(files[:max(0, MAX_BACKUPS)])
    deleted = 0
    for item in files[max(0, MAX_BACKUPS):]:
        _, size, path = item
        try:
            path.unlink(missing_ok=True)
            total -= size
            deleted += 1
        except OSError:
            kept.append(item)
    while MAX_BACKUP_BYTES > 0 and total > MAX_BACKUP_BYTES and kept:
        _, size, path = kept.pop()
        try:
            path.unlink(missing_ok=True)
            total -= size
            deleted += 1
        except OSError:
            pass
    return deleted


def cleanup_domain_if_due(domain, force=False, min_interval=60):
    domain = normalize_domain(domain)
    now = time.monotonic()
    with _CLEANUP_LOCK:
        last = float(_CLEANUP_LAST.get(domain, 0) or 0)
        if not force and now - last < max(1, int(min_interval or 0)):
            return 0
        _CLEANUP_LAST[domain] = now
    return cleanup_domain(domain, "post-receive")


def message_has_link(text, raw=""):
    return bool(re.search(r"https?://|href\s*=", str(text or "") + "\n" + str(raw or ""), re.I))


def stored_message_bytes(text, raw, attachments=None):
    total = len(str(text or "").encode("utf-8", errors="replace"))
    total += len(str(raw or "").encode("utf-8", errors="replace"))
    for item in attachments or []:
        data = item.get("data")
        if data is not None:
            total += len(data)
    return total


def backfill_message_metadata(batch_size=250, max_batches=None, domain=""):
    batch_size = max(1, min(int(batch_size or 250), 1000))
    max_batches = None if max_batches is None else max(1, int(max_batches))
    updated = 0
    batches = 0
    while max_batches is None or batches < max_batches:
        where = "metadata_version<?"
        params = [MAIL_METADATA_VERSION]
        if domain:
            where += " AND domain=?"
            params.append(_clean_domain_value(domain))
        with db() as con:
            rows = con.execute(
                f"SELECT id,subject,text,raw FROM mails WHERE {where} ORDER BY id DESC LIMIT ?",
                params + [batch_size],
            ).fetchall()
        if not rows:
            break
        values = [
            (
                extract_code(row["subject"] or "", row["text"] or ""),
                1 if message_has_link(row["text"] or "", row["raw"] or "") else 0,
                MAIL_METADATA_VERSION,
                row["id"],
            )
            for row in rows
        ]
        with db() as con:
            con.executemany(
                "UPDATE mails SET verification_code=?,has_link=?,metadata_version=? WHERE id=?",
                values,
            )
        updated += len(values)
        batches += 1
        if len(rows) < batch_size:
            break
    return updated


def database_integrity_check(force=False, min_interval=24 * 3600):
    now = int(time.time() * 1000)
    with _INTEGRITY_LOCK:
        checked_at = int(_INTEGRITY_STATE.get("checked_at") or 0)
        if not force and checked_at and now - checked_at < max(60, int(min_interval)) * 1000:
            return dict(_INTEGRITY_STATE)
        try:
            source = sqlite3.connect(Path(DB_PATH).resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
            try:
                row = source.execute("PRAGMA quick_check(1)").fetchone()
            finally:
                source.close()
            ok = bool(row and str(row[0]).lower() == "ok")
            message = "数据库完整性正常" if ok else f"数据库完整性检查失败：{row[0] if row else '无结果'}"
        except Exception as exc:
            ok = False
            message = f"数据库完整性检查失败：{exc}"
        _INTEGRITY_STATE.update({"checked_at": now, "ok": ok, "message": message})
        return dict(_INTEGRITY_STATE)


def create_backup(kind="manual"):
    with _BACKUP_LOCK:
        Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        path = str(Path(BACKUP_DIR) / f"inbox-{kind}-{ts}.sqlite3")
        temp_path = path + ".tmp"
        source = None
        dest = None
        try:
            source = sqlite3.connect(DB_PATH, timeout=30)
            dest = sqlite3.connect(temp_path, timeout=30)
            private_file(temp_path)
            source.backup(dest)
            check = dest.execute("PRAGMA quick_check(1)").fetchone()
            if not check or str(check[0]).lower() != "ok":
                raise ValueError("new backup database integrity check failed")
            dest.close()
            dest = None
            source.close()
            source = None
            size = os.path.getsize(temp_path)
            if size <= 0:
                raise ValueError("new backup is empty")
            if MAX_BACKUP_BYTES > 0 and size > MAX_BACKUP_BYTES:
                raise ValueError(f"backup size {size} exceeds limit {MAX_BACKUP_BYTES}")
            os.replace(temp_path, path)
            private_file(path)
        except BaseException:
            if dest is not None:
                dest.close()
            if source is not None:
                source.close()
            try:
                os.remove(temp_path)
            except OSError:
                pass
            raise
        now = int(time.time() * 1000)
        with db() as con:
            con.execute("INSERT INTO backup_runs (path,size,kind,created_at) VALUES (?,?,?,?)", (path, size, kind, now))
        prune_backups()
        log_op(DOMAIN, "admin" if kind == "manual" else "system", "backup.create", {"name": os.path.basename(path), "size": size, "kind": kind})
        return {"path": path, "size": size, "kind": kind, "createdAt": now}


def db_maintenance():
    try:
        with sqlite3.connect(DB_PATH, timeout=30) as con:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("PRAGMA optimize")
        integrity = database_integrity_check()
        if integrity.get("ok") is False:
            safe_log(integrity.get("message") or "database integrity check failed")
    except Exception as exc:
        safe_log(f"db maintenance error: {exc}")


def cleanup_housekeeping():
    now = int(time.time() * 1000)
    deleted = 0
    with db() as con:
        if LOG_RETENTION_DAYS > 0:
            cutoff = now - LOG_RETENTION_DAYS * 86400 * 1000
            deleted += con.execute("DELETE FROM operation_logs WHERE created_at < ?", (cutoff,)).rowcount
        if MAX_OPERATION_LOGS > 0:
            deleted += con.execute(
                """
                DELETE FROM operation_logs
                WHERE id NOT IN (
                    SELECT id FROM operation_logs
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?
                )
                """,
                (MAX_OPERATION_LOGS,),
            ).rowcount
        if FAILED_MAIL_RETENTION_DAYS > 0:
            cutoff = now - FAILED_MAIL_RETENTION_DAYS * 86400 * 1000
            deleted += con.execute("DELETE FROM failed_mails WHERE created_at < ?", (cutoff,)).rowcount
            con.execute("DELETE FROM cleanup_runs WHERE created_at < ?", (cutoff,))
            con.execute("DELETE FROM backup_runs WHERE created_at < ?", (cutoff,))
    return deleted


def list_backups():
    files = []
    for p in Path(BACKUP_DIR).glob("*.sqlite3"):
        try:
            stat = p.stat()
            files.append({"name": p.name, "path": str(p), "size": stat.st_size, "createdAt": int(stat.st_mtime * 1000)})
        except OSError:
            pass
    files.sort(key=lambda x: x["createdAt"], reverse=True)
    return files


def backup_path_by_name(name):
    name = os.path.basename(str(name or ""))
    path = Path(BACKUP_DIR) / name
    base = Path(BACKUP_DIR).resolve()
    try:
        resolved = path.resolve()
    except OSError:
        raise ValueError("backup not found")
    if base not in resolved.parents and resolved != base:
        raise ValueError("backup path invalid")
    if not resolved.exists() or resolved.suffix != ".sqlite3":
        raise ValueError("backup not found")
    return str(resolved)


def restore_backup(name):
    with _BACKUP_LOCK:
        source_path = backup_path_by_name(name)
        source = sqlite3.connect(Path(source_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
        try:
            check = source.execute("PRAGMA quick_check").fetchone()
            if not check or str(check[0]).lower() != "ok":
                raise ValueError("backup database integrity check failed")
        finally:
            source.close()
        safety = create_backup("pre-restore")
        with exclusive_db_maintenance():
            source = sqlite3.connect(Path(source_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
            dest = sqlite3.connect(DB_PATH, timeout=30)
            try:
                source.backup(dest)
            finally:
                dest.close()
                source.close()
        init_db()
        integrity = database_integrity_check(force=True)
        if not integrity.get("ok"):
            raise RuntimeError(integrity.get("message") or "restored database integrity check failed")
        invalidate_domain_cache()
        log_op(DOMAIN, "admin", "backup.restore", {"from": os.path.basename(source_path), "safety": os.path.basename(safety["path"])})
        return {"restoredFrom": source_path, "safetyBackup": safety["path"]}


def ensure_auto_backup():
    try:
        files = list_backups()
        now = time.time()
        if not files or now - (files[0]["createdAt"] / 1000) >= AUTO_BACKUP_HOURS * 3600:
            return create_backup("auto")
    except Exception as exc:
        safe_log(f"auto backup error: {exc}")
    return None


def _dns_read_name(data, offset):
    labels = []
    jumped = False
    start = offset
    for _ in range(40):
        length = data[offset]
        if length & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                start = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), (start if jumped else offset)


def dns_query(name, qtype):
    tid = secrets.randbits(16)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(part)]) + part.encode() for part in name.rstrip(".").split(".")) + b"\0"
    packet = header + qname + struct.pack("!HH", qtype, 1)
    answers = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(packet, ("1.1.1.1", 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    if len(data) < 12:
        return answers
    _, _, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = _dns_read_name(data, offset)
        offset += 4
    for _ in range(an):
        _, offset = _dns_read_name(data, offset)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata_offset = offset
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append({"type": "A", "value": socket.inet_ntoa(rdata)})
        elif rtype == 15 and rdlen >= 3:
            pref = struct.unpack("!H", rdata[:2])[0]
            host, _ = _dns_read_name(data, rdata_offset + 2)
            answers.append({"type": "MX", "priority": pref, "value": host.rstrip(".")})
        elif rtype == 5:
            host, _ = _dns_read_name(data, rdata_offset)
            answers.append({"type": "CNAME", "value": host.rstrip(".")})
    return answers


def is_cloudflare_ip(ip):
    ranges = [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ]
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(r) for r in ranges)
    except Exception:
        return False


def dns_check(domain):
    domain = normalize_domain(domain)
    mail_host = mail_host_for(domain)
    result = {"domain": domain, "mailHost": mail_host, "publicIp": PUBLIC_IP, "checkedAt": int(time.time() * 1000), "ok": False, "checks": []}
    try:
        mx = dns_query(domain, 15)
    except Exception as exc:
        mx = []
        result["checks"].append({"name": "MX 查询", "ok": False, "message": str(exc)})
    try:
        a = dns_query(mail_host, 1)
    except Exception as exc:
        a = []
        result["checks"].append({"name": "A 查询", "ok": False, "message": str(exc)})
    mx_ok = any(r.get("value", "").rstrip(".").lower() == mail_host for r in mx)
    a_values = [r["value"] for r in a if r.get("type") == "A"]
    a_ok = PUBLIC_IP in a_values
    cf_proxy = any(is_cloudflare_ip(ip) for ip in a_values)
    result["mx"] = mx
    result["a"] = a_values
    result["checks"].extend([
        {"name": "MX 指向", "ok": mx_ok, "message": f"应指向 {mail_host}，当前 {', '.join(r.get('value','') for r in mx) or '未查到'}"},
        {"name": "mail A 记录", "ok": a_ok, "message": f"应指向 {PUBLIC_IP}，当前 {', '.join(a_values) or '未查到'}"},
        {"name": "Cloudflare 灰云", "ok": not cf_proxy and a_ok, "message": "检测到 Cloudflare 代理 IP，邮件 A 记录应保持 DNS only" if cf_proxy else "未检测到明显橙云代理"},
    ])
    result["ok"] = mx_ok and a_ok and not cf_proxy
    return result


def dns_check_cached(domain, ttl=60):
    domain = normalize_domain(domain)
    now = time.monotonic()
    with _DNS_CACHE_LOCK:
        cached = _DNS_CACHE.get(domain)
        if cached and now < cached[0]:
            return dict(cached[1])
    result = dns_check(domain)
    with _DNS_CACHE_LOCK:
        _DNS_CACHE[domain] = (now + max(5, int(ttl)), dict(result))
        if len(_DNS_CACHE) > 256:
            stale = [key for key, value in _DNS_CACHE.items() if value[0] <= now]
            for key in stale:
                _DNS_CACHE.pop(key, None)
            if len(_DNS_CACHE) > 256:
                for key, _value in sorted(_DNS_CACHE.items(), key=lambda item: item[1][0])[:len(_DNS_CACHE) - 256]:
                    _DNS_CACHE.pop(key, None)
    return result


def admin_overview(root_domain=DOMAIN):
    root_domain = root_domain_for(domain_input(root_domain or DOMAIN)) or DOMAIN
    domain_where = "(domain=? OR domain LIKE ?)"
    domain_params = [root_domain, "%." + root_domain]
    domains_where = "(d.domain=? OR d.domain LIKE ?)"
    today_start = int(time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1)) * 1000)
    with db() as con:
        total_domains = con.execute(f"SELECT COUNT(*) AS c FROM mail_domains WHERE {domain_where}", domain_params).fetchone()["c"]
        usage = con.execute(
            f"SELECT COALESCE(SUM(alias_count),0) AS aliases,COALESCE(SUM(mail_count),0) AS mails "
            f"FROM domain_usage WHERE {domain_where}", domain_params
        ).fetchone()
        total_aliases = int(usage["aliases"] or 0)
        total_mails = int(usage["mails"] or 0)
        today_mails = con.execute(f"SELECT COUNT(*) AS c FROM mails WHERE {domain_where} AND received_at>=?", domain_params + [today_start]).fetchone()["c"]
        failed = con.execute("SELECT COUNT(*) AS c FROM failed_mails WHERE created_at>=?", (today_start,)).fetchone()["c"]
        auth_failed = con.execute("SELECT COUNT(*) AS c FROM operation_logs WHERE action IN ('security.auth_failed','security.auth_blocked') AND created_at>=?", (today_start,)).fetchone()["c"]
        rows = con.execute("""
            SELECT d.domain,d.owner,d.enabled,d.token_disabled,d.alias_limit,d.mail_limit,d.storage_limit_mb,
            COALESCE(u.alias_count,0) AS alias_count,
            COALESCE(u.mail_count,0) AS mail_count,
            (SELECT COUNT(*) FROM mails m WHERE m.domain=d.domain AND m.received_at>=?) AS today_count,
            (SELECT MAX(m.received_at) FROM mails m WHERE m.domain=d.domain) AS latest
            FROM mail_domains d
            LEFT JOIN domain_usage u ON u.domain=d.domain
            WHERE """ + domains_where + """
            ORDER BY today_count DESC, mail_count DESC
            LIMIT 20
        """, (today_start,) + tuple(domain_params)).fetchall()
    risks = []
    for r in rows:
        if int(r["mail_count"] or 0) >= int(r["mail_limit"] or DEFAULT_MAIL_LIMIT) * 0.9:
            risks.append(f"{r['domain']} 邮件数量接近上限")
        if int(r["alias_count"] or 0) >= int(r["alias_limit"] or DEFAULT_ALIAS_LIMIT) * 0.9:
            risks.append(f"{r['domain']} 别名数量接近上限")
        if int(r["today_count"] or 0) >= 500:
            risks.append(f"{r['domain']} 今日收信量偏高")
        if not int(r["enabled"] or 0):
            risks.append(f"{r['domain']} 已停用")
    if failed:
        risks.append(f"今日有 {failed} 条异常收信或 Webhook 失败记录")
    if auth_failed >= 10:
        risks.append(f"今日有 {auth_failed} 次密钥失败尝试，已启用失败限流")
    try:
        dns = dns_check_cached(root_domain)
    except Exception as exc:
        dns = {"domain": root_domain, "ok": False, "checks": [{"name": "DNS检查", "ok": False, "message": str(exc)}]}
    service = health_report()
    return {
        "domains": total_domains,
        "aliases": total_aliases,
        "mails": total_mails,
        "todayMails": today_mails,
        "dbSize": db_file_size(),
        "backupSize": backup_total_size(),
        "failedToday": failed,
        "authFailedToday": auth_failed,
        "risks": risks[:10],
        "topDomains": [dict(r) for r in rows],
        "dns": dns,
        "service": service,
    }


def health_report(force=False):
    now = time.monotonic()
    with _HEALTH_LOCK:
        cached = _HEALTH_CACHE.get("data")
        if cached and not force and now < float(_HEALTH_CACHE.get("expires") or 0):
            return dict(cached)

    smtp_ok = False
    smtp_message = "SMTP 未响应"
    probe_host = "127.0.0.1" if SMTP_HOST in ("", "0.0.0.0", "::") else SMTP_HOST
    try:
        with socket.create_connection((probe_host, SMTP_PORT), timeout=2) as sock:
            greeting = sock.recv(64)
        smtp_ok = greeting.startswith(b"220")
        smtp_message = "SMTP 正常" if smtp_ok else "SMTP 返回了异常响应"
    except Exception as exc:
        smtp_message = f"SMTP 不可用：{exc}"

    database_ok = False
    database_message = "数据库不可用"
    try:
        with db() as con:
            con.execute("SELECT 1").fetchone()
        integrity = dict(_INTEGRITY_STATE)
        database_ok = integrity.get("ok") is not False
        database_message = integrity.get("message") if integrity.get("ok") is False else "数据库正常"
    except Exception as exc:
        integrity = dict(_INTEGRITY_STATE)
        database_message = f"数据库不可用：{exc}"

    try:
        db_disk = shutil.disk_usage(DB_DIR)
        backup_disk = shutil.disk_usage(BACKUP_DIR)
        disk_free = min(int(db_disk.free), int(backup_disk.free))
        disk_total = int(db_disk.total)
        backup_disk_free = int(backup_disk.free)
    except OSError:
        disk_free, disk_total, backup_disk_free = 0, 0, 0
    disk_ok = disk_free > max(64 * 1024 * 1024, MIN_DISK_FREE_BYTES)
    backup_files = list_backups()
    backup_size = backup_total_size()
    latest_backup_at = max((int(item.get("createdAt") or 0) for item in backup_files), default=0)
    latest_backup_age_hours = ((now_ms() - latest_backup_at) / 3600000) if latest_backup_at else None
    backup_recent = latest_backup_age_hours is not None and latest_backup_age_hours <= max(1, BACKUP_MAX_AGE_HOURS)
    backup_ok = bool(backup_files) and backup_recent and (MAX_BACKUP_BYTES <= 0 or backup_size <= MAX_BACKUP_BYTES)
    issues = []
    if not smtp_ok:
        issues.append(smtp_message)
    if not database_ok:
        issues.append(database_message)
    if not disk_ok:
        issues.append(f"数据或备份磁盘剩余空间不足 {MIN_DISK_FREE_BYTES} 字节")
    if not backup_ok:
        if not backup_files:
            issues.append("尚无可用备份")
        elif not backup_recent:
            issues.append(f"最新备份已超过 {BACKUP_MAX_AGE_HOURS} 小时")
        elif MAX_BACKUP_BYTES > 0 and backup_size > MAX_BACKUP_BYTES:
            issues.append("备份目录已超过容量上限")
    ok = smtp_ok and database_ok and disk_ok and backup_ok
    report = {
        "ok": ok,
        "status": "healthy" if ok else "degraded",
        "http": True,
        "smtp": smtp_ok,
        "database": database_ok,
        "disk": disk_ok,
        "backups": backup_ok,
        "diskFree": disk_free,
        "diskTotal": disk_total,
        "backupDiskFree": backup_disk_free,
        "dbSize": db_file_size(),
        "backupSize": backup_size,
        "backupLimit": MAX_BACKUP_BYTES,
        "backupCount": len(backup_files),
        "latestBackupAt": latest_backup_at or None,
        "latestBackupAgeHours": round(latest_backup_age_hours, 2) if latest_backup_age_hours is not None else None,
        "backupMaxAgeHours": BACKUP_MAX_AGE_HOURS,
        "databaseIntegrity": integrity,
        "issues": issues,
        "components": {
            "http": {"ok": True, "message": "HTTP 正常"},
            "smtp": {"ok": smtp_ok, "message": smtp_message},
            "database": {"ok": database_ok, "message": database_message},
            "disk": {"ok": disk_ok, "message": "数据与备份磁盘空间正常" if disk_ok else "数据或备份磁盘空间不足"},
            "backups": {"ok": backup_ok, "message": "备份存在且时效正常" if backup_ok else "备份缺失、过期或超过上限"},
        },
        "checkedAt": now_ms(),
    }
    with _HEALTH_LOCK:
        _HEALTH_CACHE["data"] = dict(report)
        _HEALTH_CACHE["expires"] = now + 5
    return report


def domains_under_root(root_domain):
    root_domain = root_domain_for(domain_input(root_domain or DOMAIN)) or DOMAIN
    with db() as con:
        rows = con.execute("""
            SELECT domain FROM mail_domains
            WHERE domain=? OR domain LIKE ?
            ORDER BY CASE WHEN domain=? THEN 0 ELSE 1 END, domain
        """, (root_domain, "%." + root_domain, root_domain)).fetchall()
    return [r["domain"] for r in rows]


def bulk_save_subdomains(values, root_domain, owner="", issue_tokens=False):
    root_domain = root_domain_for(domain_input(root_domain or DOMAIN)) or DOMAIN
    if isinstance(values, str):
        items = re.split(r"[\s,;，；]+", values)
    else:
        items = values if isinstance(values, list) else []
    cleaned = []
    for item in items:
        value = str(item or "").strip().lower()
        if value and value not in cleaned:
            cleaned.append(value)
    if not cleaned:
        raise ValueError("subdomain list required")
    if len(cleaned) > 200:
        raise ValueError("batch subdomain limit is 200")
    existing = set(list_domains(refresh=True))
    created, existed, errors, token_rows = [], [], [], []
    for value in cleaned:
        try:
            domain = domain_input(value, root_domain)
            if domain == root_domain:
                raise ValueError("main domain cannot be added as subdomain")
            if not domain_in_root(domain, root_domain):
                raise ValueError("subdomain is outside current main domain")
            was_existing = domain in existing
            save_domain(domain, "batch", root_domain)
            if owner:
                update_domain_settings(domain, {"owner": owner})
            token = ""
            if issue_tokens:
                token = set_domain_token(domain)
            existing.add(domain)
            (existed if was_existing else created).append(domain)
            token_rows.append({"domain": domain, "path": domain_path(domain), "token": token})
        except Exception as exc:
            errors.append({"input": value, "message": str(exc)})
    return {"created": created, "existing": existed, "errors": errors, "tokens": token_rows}


def dns_check_many(domains, limit=80):
    selected = list(domains or [])[:limit]
    results = [None] * len(selected)

    def check_one(index, domain):
        try:
            return index, dns_check(domain)
        except Exception as exc:
            return index, {"domain": domain, "ok": False, "checks": [{"name": "DNS检查", "ok": False, "message": str(exc)}]}

    if selected:
        workers = min(8, len(selected))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(check_one, i, domain) for i, domain in enumerate(selected)]
            for future in as_completed(futures):
                index, result = future.result()
                results[index] = result
    return {"checked": len(results), "limited": len(domains or []) > limit, "data": results}


def domain_export_lines(domains, base_url="", include_tokens=True, include_dns=True):
    base_url = str(base_url or "").rstrip("/")
    with db() as con:
        placeholders = ",".join("?" for _ in domains) or "''"
        rows = con.execute(f"SELECT domain,token,enabled,token_disabled,owner,note FROM mail_domains WHERE domain IN ({placeholders}) ORDER BY domain", domains).fetchall() if domains else []
    by_domain = {r["domain"]: r for r in rows}
    lines = []
    for domain in domains:
        row = by_domain.get(domain)
        token = (row["token"] or "") if row else ""
        path = domain_path(domain)
        lines.append(f"域名: {domain}")
        lines.append(f"页面: {base_url}{path}" if base_url else f"页面: {path}")
        if row:
            lines.append(f"状态: 域名{'启用' if int(row['enabled'] or 0) else '停用'} / Token {'禁用' if int(row['token_disabled'] or 0) else '启用'}")
            if row["owner"]:
                lines.append(f"所有者: {row['owner']}")
        if include_tokens:
            lines.append(f"Token: {token or '未生成'}")
        if include_dns:
            lines.extend([
                "DNS:",
                f"  MX  Name: {mx_name_for(domain)}",
                f"  MX  Mail server: {mail_host_for(domain)}",
                "  MX  Priority: 10",
                "  A   Name: mail",
                f"  A   IPv4 address: {PUBLIC_IP}",
                "  Proxy status: DNS only / 灰云",
            ])
        lines.append("")
    return lines


def list_aliases_page(domain, query="", page=1, page_size=50):
    domain = normalize_domain(domain)
    query = str(query or "").lower().strip()
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or 50), 200))
    offset = (page - 1) * page_size
    where = ["a.domain=?"]
    params = [domain]
    if query:
        where.append("(a.email LIKE ? OR COALESCE(a.note,'') LIKE ?)")
        like = "%" + query + "%"
        params.extend([like, like])
    where_sql = " AND ".join(where)
    with db() as con:
        total = con.execute(f"SELECT COUNT(*) AS c FROM aliases a WHERE {where_sql}", params).fetchone()["c"]
        rows = con.execute(
            f"""
            SELECT a.email,a.note,a.created_at,a.share_token,a.share_enabled,a.share_created_at,a.share_last_used_at,
                   a.mail_count AS count,a.latest_mail_at AS latest
            FROM aliases a
            WHERE {where_sql}
            ORDER BY a.activity_at DESC, a.email ASC
            LIMIT ? OFFSET ?
            """,
            params + [page_size, offset],
        ).fetchall()
    return rows, total, page, page_size


def save_aliases(values, note="", domain=DOMAIN, limit=10000):
    domain = normalize_domain(domain)
    cfg = domain_config(domain)
    if not int(cfg.get("enabled") or 0):
        raise ValueError("domain disabled")
    if not isinstance(values, list):
        raise ValueError("aliases must be a list")
    if len(values) > limit:
        raise ValueError(f"too many aliases, max {limit}")
    seen = set()
    emails = []
    errors = []
    for idx, value in enumerate(values, 1):
        try:
            em = alias_email(value, domain)
            if not em.endswith("@" + domain):
                raise ValueError("alias domain mismatch")
            if em not in seen:
                seen.add(em)
                emails.append(em)
        except Exception as exc:
            errors.append({"index": idx, "value": str(value or "")[:120], "message": str(exc)})
    if not emails:
        return {"created": 0, "existing": 0, "total": 0, "errors": errors}
    existing_set = set()
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        usage = con.execute("SELECT alias_count FROM domain_usage WHERE domain=?", (domain,)).fetchone()
        current = int(usage["alias_count"] or 0) if usage else 0
        for i in range(0, len(emails), 800):
            chunk = emails[i:i + 800]
            rows = con.execute(
                "SELECT email FROM aliases WHERE email IN (%s)" % ",".join("?" for _ in chunk),
                chunk,
            ).fetchall()
            existing_set.update(r["email"] for r in rows)
        new_count = len([em for em in emails if em not in existing_set])
        allowed_new = max(0, int(cfg.get("alias_limit") or DEFAULT_ALIAS_LIMIT) - current)
        if new_count > allowed_new:
            raise ValueError(f"alias limit reached, can add {allowed_new} more")
        now = int(time.time() * 1000)
        created = 0
        for em in emails:
            cur = con.execute(
                "INSERT OR IGNORE INTO aliases (email,domain,note,created_at) VALUES (?,?,?,?)",
                (em, domain, str(note or "batch")[:300], now),
            )
            if cur.rowcount:
                created += 1
    return {"created": created, "existing": len(emails) - created, "total": len(emails), "errors": errors}


def delete_alias(email, domain=DOMAIN, allowed_domain=""):
    domain = normalize_domain(domain)
    em = alias_email(email, domain)
    if not em.endswith("@" + domain):
        raise ValueError("alias domain mismatch")
    if not scope_allows_domain(allowed_domain, domain):
        raise PermissionError("cannot delete alias in this domain")
    with db() as con:
        cur = con.execute("DELETE FROM aliases WHERE email=?", (em,))
    return em, cur.rowcount


def clear_domain_aliases(domain, allowed_domain=""):
    domain = normalize_domain(domain)
    if not scope_allows_domain(allowed_domain, domain):
        raise PermissionError("cannot clear aliases in this domain")
    with db() as con:
        cur = con.execute("DELETE FROM aliases WHERE domain=?", (domain,))
    return cur.rowcount


def delete_domain_tree(domain, auth):
    domain = normalize_domain(domain)
    if not domain:
        raise ValueError("domain required")
    role = (auth or {}).get("role")
    if role not in ("admin", "root"):
        raise PermissionError("domain manager token required")
    root_domain = root_domain_for(domain, refresh=True) or domain
    is_root = domain == root_domain
    if is_root:
        if role != "admin":
            raise PermissionError("admin token required to delete main domain")
        if domain == DOMAIN:
            raise ValueError("default main domain cannot be deleted")
    elif role == "root" and not domain_in_root(domain, auth.get("domain") or ""):
        raise PermissionError("cannot delete this subdomain")
    with db() as con:
        exists = con.execute("SELECT domain FROM mail_domains WHERE domain=?", (domain,)).fetchone()
        if not exists:
            raise ValueError("domain not found")
        rows = con.execute(
            "SELECT domain FROM mail_domains WHERE domain=? OR domain LIKE ? ORDER BY LENGTH(domain) DESC",
            (domain, "%." + domain),
        ).fetchall()
        domains = [r["domain"] for r in rows]
        if not domains:
            return {"domains": 0, "aliases": 0, "mails": 0, "attachments": 0, "domainList": []}
        placeholders = ",".join("?" for _ in domains)
        mail_rows = con.execute(f"SELECT id FROM mails WHERE domain IN ({placeholders})", domains).fetchall()
        mail_ids = [r["id"] for r in mail_rows]
        attachments = 0
        for i in range(0, len(mail_ids), 800):
            chunk = mail_ids[i:i + 800]
            if chunk:
                attachments += con.execute("DELETE FROM attachments WHERE mail_id IN (%s)" % ",".join("?" for _ in chunk), chunk).rowcount
        mails = con.execute(f"DELETE FROM mails WHERE domain IN ({placeholders})", domains).rowcount
        aliases = con.execute(f"DELETE FROM aliases WHERE domain IN ({placeholders})", domains).rowcount
        deleted_domains = con.execute(f"DELETE FROM mail_domains WHERE domain IN ({placeholders})", domains).rowcount
        con.execute(f"DELETE FROM domain_usage WHERE domain IN ({placeholders})", domains)
    invalidate_domain_cache()
    return {"domains": deleted_domains, "aliases": aliases, "mails": mails, "attachments": attachments, "domainList": domains}


def normalize_alias_share_token(token):
    token = str(token or "").strip()
    if not ALIAS_SHARE_TOKEN_RE.fullmatch(token):
        return ""
    return token


def new_alias_share_token():
    return ALIAS_SHARE_TOKEN_PREFIX + secrets.token_urlsafe(36)


def alias_share_path(token):
    token = normalize_alias_share_token(token)
    if not token:
        return ""
    return "/code/" + token


def get_alias_by_share_token(token, touch=False):
    token = normalize_alias_share_token(token)
    if not token:
        return None
    with db() as con:
        row = con.execute("""
            SELECT a.email,a.domain,a.note,a.created_at,a.share_token,a.share_enabled,a.share_created_at,a.share_last_used_at,
                   d.enabled AS domain_enabled
            FROM aliases a
            JOIN mail_domains d ON d.domain=a.domain
            WHERE a.share_token=? AND a.share_enabled=1
        """, (token,)).fetchone()
        if not row:
            return None
        if not int(row["domain_enabled"] or 0):
            return None
        data = dict(row)
        if touch:
            con.execute("UPDATE aliases SET share_last_used_at=? WHERE email=?", (now_ms(), data["email"]))
            data["share_last_used_at"] = now_ms()
    return data


def ensure_alias_share(email, domain=DOMAIN, reset=False, enabled=True):
    domain = normalize_domain(domain)
    em = alias_email(email, domain)
    if not em.endswith("@" + domain):
        raise ValueError("alias domain mismatch")
    now = now_ms()
    with db() as con:
        row = con.execute("SELECT email,domain,share_token,share_enabled,share_created_at,share_last_used_at FROM aliases WHERE email=? AND domain=?", (em, domain)).fetchone()
        if not row:
            raise ValueError("alias not found")
        if not enabled:
            con.execute("UPDATE aliases SET share_enabled=0 WHERE email=?", (em,))
            token = row["share_token"] or ""
            return {
                "email": em,
                "domain": domain,
                "enabled": False,
                "token": token,
                "path": alias_share_path(token),
                "createdAt": row["share_created_at"],
                "lastUsedAt": row["share_last_used_at"],
            }
    if reset or not normalize_alias_share_token(row["share_token"] or ""):
        last_error = None
        for _ in range(10):
            token = new_alias_share_token()
            try:
                with db() as con:
                    con.execute(
                        "UPDATE aliases SET share_token=?, share_enabled=1, share_created_at=?, share_last_used_at=NULL WHERE email=? AND domain=?",
                        (token, now, em, domain),
                    )
                return {
                    "email": em,
                    "domain": domain,
                    "enabled": True,
                    "token": token,
                    "path": alias_share_path(token),
                    "createdAt": now,
                    "lastUsedAt": None,
                }
            except sqlite3.IntegrityError as exc:
                last_error = exc
        raise RuntimeError("failed to generate unique alias share token") from last_error
    token = row["share_token"]
    with db() as con:
        con.execute("UPDATE aliases SET share_enabled=1 WHERE email=? AND domain=?", (em, domain))
    return {
        "email": em,
        "domain": domain,
        "enabled": True,
        "token": token,
        "path": alias_share_path(token),
        "createdAt": row["share_created_at"],
        "lastUsedAt": row["share_last_used_at"],
    }


def alias_share_public_messages(email, query="", page=1, page_size=50):
    em = normalize_addr(email)
    domain = domain_of_email(em)
    if not domain:
        raise ValueError("unsupported mail domain")
    rows, total, page, page_size = list_messages_page(
        domain,
        email=em,
        query=query,
        page=page,
        page_size=min(int(page_size or 50), 100),
        filters={},
    )
    return rows, total, page, page_size


def export_alias_share_urls(domain, base_url=""):
    domain = normalize_domain(domain)
    base_url = str(base_url or "").rstrip("/")
    with db() as con:
        rows = con.execute("SELECT email,share_token,share_enabled FROM aliases WHERE domain=? ORDER BY email ASC", (domain,)).fetchall()
    lines = []
    for row in rows:
        token = row["share_token"] or ""
        if not token or not int(row["share_enabled"] or 0):
            data = ensure_alias_share(row["email"], domain, reset=False, enabled=True)
            token = data["token"]
        path = alias_share_path(token)
        lines.append(f"{row['email']}----{base_url}{path}" if base_url else f"{row['email']}----{path}")
    return lines


def api_docs_markdown(base_url=""):
    base_url = str(base_url or "").rstrip("/") or f"http://{PUBLIC_IP}:{HTTP_PORT}"
    roots = root_domains(refresh=True)
    root_text = ", ".join(roots) or DOMAIN
    primary_root = roots[0] if roots else DOMAIN
    secondary_root = roots[1] if len(roots) > 1 else primary_root
    generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    content = f"""# Ferret Mail API 文档

生成时间：{generated}
服务地址：`{base_url}`
当前主域名：`{root_text}`
文档状态：与当前运行程序动态同步

本服务只提供收件、别名、验证码、附件、接码链接和管理能力，不提供发信 API。本文档公开可下载，不包含任何真实 Token；`YOUR_TOKEN`、`ADMIN_TOKEN` 和 `ALIAS_SHARE_TOKEN` 都必须由部署者替换。

## 1. 基础规则

### 鉴权

```http
Authorization: YOUR_TOKEN
```

也可以使用 `X-Token: YOUR_TOKEN`。不要把 Token 写进公开前端代码。

权限分为三类：

- 全局管理员 Token：可管理全部主域名、子域名、备份、日志和运维接口。
- 主域名 Token：可管理该主域名及其子域名，不能管理其他主域名。
- 域名 Token：只能访问对应域名的别名和邮件。

### 通用响应

大多数 JSON 接口返回：

```json
{{"code":200,"message":"success","data":{{}}}}
```

常见错误：`400` 参数错误，`401` Token 错误或失效，`403` 权限不足，`404` 不存在，`429` 触发限流，`413` 请求体过大。

### 时间格式

接口里的时间字段通常是毫秒时间戳，例如 `receivedAt`、`createdAt`、`latest`。

## 2. 最常用取件流程

### 流程 A：已知邮箱别名，等待验证码

1. 确保别名存在：`POST /ui-api/aliases`
2. 长轮询等待新邮件：`GET /ui-api/changes`
3. 拉取邮件列表：`GET /ui-api/messages`
4. 读取单封详情：`GET /ui-api/message?id=邮件ID`

### 流程 B：不提前创建别名，自动创建后取件

直接给 `new-user@example.org` 发邮件，系统收到邮件时会自动创建别名。对接程序监听整个域名：

```http
GET /ui-api/changes?domain=example.org&since=0
Authorization: YOUR_TOKEN
```

返回 `changed=true` 后，用返回的 `latestEmail` 调用邮件列表：

```http
GET /ui-api/messages?domain=example.org&email=new-user@example.org
Authorization: YOUR_TOKEN
```

### 流程 C：公开接码链接取件

先生成独立接码链接：

```http
POST /ui-api/alias-share-token
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.com","email":"a@example.com","enabled":true}}
```

返回的 `data.url` 可以给其他程序或用户只读取件。公开接口不需要后台 Token，只需要链接里的 `alias_...` token。

## 3. 邮件取件接口

### 当前域名 / 主域名 / 其他主域名取件

```http
GET /ui-api/messages?domain=example.org&page=1&pageSize=50
Authorization: YOUR_TOKEN
```

把 `domain` 换成任意已接入主域名即可，例如 `example.com`、`example.org`、`example.com`。

### 子域名取件

```http
GET /ui-api/messages?domain=team.example.org&page=1&pageSize=50
Authorization: YOUR_TOKEN
```

### 指定别名取件

```http
GET /ui-api/messages?domain=team.example.org&email=a@team.example.org&page=1&pageSize=50
Authorization: YOUR_TOKEN
```

### 邮件列表参数

`domain` 必填或默认当前主域名；`email` 指定别名；`page/pageSize` 分页；`q` 搜索全文；`from`、`to`、`subject` 分字段筛选；`code` 搜验证码；`hasCode=1`、`hasLink=1`、`unread=1`、`today=1`、`starred=1`、`pinned=1` 是布尔筛选；`dateFrom/dateTo` 是日期筛选。

返回 `data` 为邮件列表，常用字段：

```json
{{"id":123,"toEmail":"a@example.org","fromEmail":"noreply@example.com","subject":"验证码","text":"...","code":"123456","receivedAt":1780000000000,"isRead":false,"starred":false,"pinned":false,"hasLink":true}}
```

### 单封邮件详情

```http
GET /ui-api/message?id=123
Authorization: YOUR_TOKEN
```

返回正文、HTML、原始源码、邮件头、链接、附件列表和识别出的验证码。调用后会自动标记这封邮件为已读。

### 附件下载

```http
GET /ui-api/attachment?id=附件ID
Authorization: YOUR_TOKEN
```

附件 ID 来自单封邮件详情里的 `attachments`。超过保存上限的附件只返回元信息，不能下载。

### 实时监听新邮件

```http
GET /ui-api/changes?domain=example.org&email=a@example.org&since=0
Authorization: YOUR_TOKEN
```

`email` 可省略；省略时监听整个域名。接口最长等待约 25 秒。返回字段包含 `changed`、`latest`、`latestId`、`latestEmail`、`latestReceivedAt`、`count`。收到 `changed=true` 后再调用 `/ui-api/messages` 拉取最新邮件。

## 4. 邮件状态、批量和删除接口

### 标记已读、星标、置顶

```http
POST /ui-api/message-state
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"ids":[123,124],"isRead":true,"starred":true,"pinned":false}}
```

也可传 `id` 或 `messageId`。返回 `changed` 为实际修改数量。

### 批量邮件操作

```http
POST /ui-api/messages-bulk
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"ids":[123,124],"action":"read"}}
```

`action` 可用：`delete`、`read`、`unread`、`star`、`unstar`、`pin`、`unpin`。

### 删除单封邮件

```http
POST /ui-api/delete-message
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"id":123}}
```

### 清空某个别名邮件

```http
POST /ui-api/clear-alias-messages
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"email":"a@example.org","confirm":"a@example.org"}}
```

### 清空某个域名邮件

```http
POST /ui-api/clear-messages
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.org","confirm":"example.org"}}
```

清空类接口会先创建备份，但删除后的页面数据不可恢复到单条状态，请谨慎调用。

## 5. 别名接口

### 创建一个别名

```http
POST /ui-api/aliases
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.org","email":"a","note":"optional"}}
```

`email` 可以写完整邮箱，也可以只写前缀。不存在的收件别名在收到邮件时也会自动创建。

### 批量创建别名

```http
POST /ui-api/bulk-aliases
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.org","aliases":["a","b","c"],"note":"batch"}}
```

一次最多 10000 个别名。

### 别名列表

```http
GET /ui-api/aliases?domain=example.org&page=1&pageSize=50&q=a
Authorization: YOUR_TOKEN
```

返回字段包含 `email`、`count`、`latest`、`shareEnabled`、`sharePath`、`shareCreatedAt`、`shareLastUsedAt`。

### 删除别名

```http
POST /ui-api/delete-alias
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.org","email":"a@example.org","confirm":"a@example.org"}}
```

只删除别名列表记录，不会同时删除邮件。

### 清空域名下所有别名

```http
POST /ui-api/clear-aliases
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.org","confirm":"example.org","phrase":"清空别名"}}
```

## 6. 独立接码链接接口

### 生成、重置或禁用接码链接

```http
POST /ui-api/alias-share-token
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.org","email":"a@example.org","enabled":true,"reset":false}}
```

返回 `data.url`、`data.path`、`data.enabled`。为安全起见，后台接口不会直接返回原始 share token 字段。

禁用：

```json
{{"domain":"example.org","email":"a@example.org","enabled":false}}
```

### 导出当前域名所有接码链接

```http
POST /ui-api/alias-share-export
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.org"}}
```

返回 TXT 文件。没有链接或未启用的别名会自动生成并启用链接。

### 公开接码取件

```http
GET /public-api/alias-share?token=ALIAS_SHARE_TOKEN&page=1&pageSize=50&q=验证码
GET /public-api/alias-share/message?token=ALIAS_SHARE_TOKEN&id=123
GET /public-api/alias-share/changes?token=ALIAS_SHARE_TOKEN&since=0
```

公开接口只允许访问这个接码链接对应的单个别名。

公开页面入口：

```http
GET /code/ALIAS_SHARE_TOKEN
```

## 7. 主域名、子域名和 DNS 接口

### 域名列表和 Token 面板数据

```http
GET /ui-api/domains?root=example.org&page=1&pageSize=20
Authorization: YOUR_TOKEN
```

返回域名列表、统计、页面路径、DNS 配置信息、域名 Token、主域名 tabs 等。全局管理员可看到所有主域名；主域名 Token 只能看到自己的主域名。

### 添加子域名

```http
POST /ui-api/domains
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"root":"example.org","domain":"team","owner":"owner"}}
```

`domain` 可以写 `team`，也可以写完整 `team.example.org`。

### 批量添加子域名

```http
POST /ui-api/domains-bulk
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"root":"example.org","domains":"team\\ncode\\napi","owner":"owner","issueTokens":true}}
```

一次最多 200 个子域名。`issueTokens=true` 时会同时生成域名 Token。

### 添加其他主域名

```http
POST /ui-api/domains
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.com","root":"example.com","owner":"owner"}}
```

只有全局管理员 Token 可以添加其他主域名。

### 修改域名设置

```http
POST /ui-api/domain-settings
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.org","owner":"owner","note":"备注","enabled":1,"token_disabled":0,"retention_hours":72,"cleanup_max_mails":0,"alias_limit":500000,"mail_limit":50000,"storage_limit_mb":1024,"brand_title":"标题","brand_desc":"说明","default_alias":"a","theme_color":"#2563eb","webhook_url":"https://example.com/hook","webhook_enabled":1}}
```

可修改字段：`enabled`、`token_disabled`、`retention_hours`、`cleanup_max_mails`、`alias_limit`、`mail_limit`、`storage_limit_mb`、`note`、`owner`、`brand_title`、`brand_desc`、`default_alias`、`theme_color`、`webhook_url`、`webhook_enabled`。

停用域名时必须额外传 `confirmDomain`，值为完整域名。

Webhook 会在收到新邮件后 POST 邮件摘要，字段包含 `event`、`domain`、`id`、`toEmail`、`fromEmail`、`subject`、`code`、`receivedAt`。

### 生成或重置域名 Token

```http
POST /ui-api/domain-token
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"example.com"}}
```

也可以传自定义 `token`，长度必须为 24-256 个字符。返回 `data.token` 和 `data.path`。

### 删除子域名或其他主域名

```http
POST /ui-api/delete-domain
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"domain":"team.example.org","confirm":"team.example.org","phrase":"删除子域名"}}
```

删除其他主域名时：

```json
{{"domain":"example.com","confirm":"example.com","phrase":"删除主域名"}}
```

删除前会自动创建 `pre-delete-domain` 备份。删除子域名会删除该子域名及其下级域名、别名、邮件和附件；删除主域名会删除该主域名及其全部子域名、别名、邮件和附件。删除主域名仅全局管理员 Token 可用，默认主域名不能删除。

### 单个 DNS 检查

```http
GET /ui-api/dns-check?domain=example.org
Authorization: YOUR_TOKEN
```

返回 `ok`、`mailHost`、`publicIp`、`mx`、`a`、`checks`。检查内容包括 MX、mail A 记录、Cloudflare 灰云。

### 批量 DNS 检查

```http
GET /ui-api/dns-check-bulk?root=example.org&scope=current
Authorization: YOUR_TOKEN
```

`scope=current` 检查当前主域名及其子域名；全局管理员可用 `scope=all` 检查全部域名。单次最多返回 80 个域名的检查结果。

### 导出 Token 或 Cloudflare 配置

```http
GET /ui-api/domain-export?type=current-tokens&root=example.org
GET /ui-api/domain-export?type=root-tokens
GET /ui-api/domain-export?type=dns-current&root=example.org
GET /ui-api/domain-export?type=dns-all
Authorization: YOUR_TOKEN
```

`root-tokens` 只允许全局管理员使用。`dns-all` 全局管理员导出全部域名；主域名 Token 只导出自己的主域名和子域名。

## 8. 后台总览和运维接口

### 登录权限检查

```http
GET /ui-api/auth-check
Authorization: YOUR_TOKEN
```

返回 `role`、`domain`、`canManageDomains`、`canAddRootDomains`。

### 主域名运行总览

```http
GET /ui-api/admin/overview?root=example.org
Authorization: YOUR_TOKEN
```

主域名 Token 和全局管理员 Token 可用。返回域名数量、别名数量、邮件数量、今日收信、风险提醒、热门域名统计和 DNS 检查状态。

### 全局健康检查

```http
GET /ui-api/admin/health
Authorization: ADMIN_TOKEN
```

全局管理员 Token 可用。返回 HTTP、SMTP、磁盘、数据库、备份占用等状态。

### 备份

```http
GET /ui-api/admin/backups
GET /ui-api/admin/backup-download?name=BACKUP_NAME
POST /ui-api/admin/backup-create
POST /ui-api/admin/backup-restore
Authorization: ADMIN_TOKEN
```

恢复备份请求体：

```json
{{"name":"backup.sqlite3","confirmName":"backup.sqlite3","confirm":"恢复备份"}}
```

恢复会覆盖当前数据库，请只在确认需要回滚时调用。

### 日志和异常

```http
GET /ui-api/admin/audit
GET /ui-api/admin/audit?domain=example.org
GET /ui-api/admin/audit?format=csv
GET /ui-api/admin/failed-mails
GET /ui-api/admin/cleanup-runs
Authorization: ADMIN_TOKEN
```

### 手动清理兼容接口

```http
POST /admin/cleanup
POST /api/admin/cleanup
Authorization: ADMIN_TOKEN
```

## 9. 旧版兼容接口

这些接口保留给旧程序，不建议新对接优先使用：

```http
POST /public/addUser
POST /api/public/addUser
Authorization: ADMIN_TOKEN
Content-Type: application/json

{{"list":["a@example.org","b@example.org"]}}
```

```http
POST /public/emailList
POST /api/public/emailList
Authorization: YOUR_TOKEN
Content-Type: application/json

{{"email":"a@example.org","size":20}}
```

## 10. 无鉴权接口

```http
GET /health
GET /api-docs.md
GET /usage-guide.md
GET /mail
GET /mail/example.org
GET /code/ALIAS_SHARE_TOKEN
```

`/mail/...` 是网页面板入口，不是 JSON API。
"""
    return (
        content
        .replace("example.com", "{{DOC_PRIMARY_ROOT}}")
        .replace("example.org", "{{DOC_SECONDARY_ROOT}}")
        .replace("127.0.0.1", "{{DOC_PUBLIC_IP}}")
        .replace("{{DOC_PRIMARY_ROOT}}", primary_root)
        .replace("{{DOC_SECONDARY_ROOT}}", secondary_root)
        .replace("{{DOC_PUBLIC_IP}}", PUBLIC_IP)
    )


def usage_guide_markdown(base_url=""):
    base_url = str(base_url or "").rstrip("/") or f"http://{PUBLIC_IP}:{HTTP_PORT}"
    roots = root_domains(refresh=True)
    first_root = roots[0] if roots else DOMAIN
    generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    return f"""# Ferret Mail 使用教程

生成时间：{generated}
面板入口：`{base_url}/mail`
文档状态：与当前运行程序动态同步

Ferret Mail 只负责收件，不提供发信能力。后台提供天光、墨玉、素纸三套全局浅色主题和 `#17191d` 深灰模式，并支持响应式布局和减少动态效果。

## 最核心：接入一个主域名并正常收件

1. 进入 Cloudflare，打开你的主域名 DNS 记录页。
2. 添加 MX 记录：
   - Type: `MX`
   - Name: `@`
   - Mail server: `mail.{first_root}`
   - Priority: `10`
3. 添加 A 记录：
   - Type: `A`
   - Name: `mail`
   - IPv4 address: `{PUBLIC_IP}`
   - Proxy status: `DNS only / 灰云`
4. 等待 DNS 生效，在面板里点 `DNS 检查`。
5. 用 `a@{first_root}` 收一封测试邮件，能收到就接入成功。

注意：邮件 A 记录不能开橙云代理，否则 SMTP 收信会异常。

## 创建子域名

1. 打开主域名页面，例如 `{base_url}/mail/{first_root}`。
2. 登录 Token。
3. 进入 `域名管理与接入`。
4. 在新增区域输入 `team`，会生成 `team.{first_root}`。
5. 按页面显示的 Cloudflare 配置添加对应 DNS；不同层级的 MX Name 以面板为准。

## 创建别名

1. 在左侧 `新建别名` 输入前缀，例如 `a`。
2. 保存后邮箱就是 `a@{first_root}`。
3. 如果没有提前创建别名，系统收到邮件时也会自动创建对应别名。

## 批量生成、搜索和邮件筛选

1. 展开 `批量生成`，按序号、日期或随机规则预览并创建别名。
2. 在 `邮箱别名` 中展开 `搜索与批量操作`，搜索、分页或导出接码链接。
3. 在邮件区展开 `筛选与批量操作`，按关键词、发件人、收件人、主题、验证码、链接、未读、星标、置顶和日期筛选。
4. HTML 邮件会显示在隔离的白色阅读画布中；读取详情会把邮件标为已读。

## 创建其他主域名

1. 使用全局管理员 Token 登录任意主域名后台。
2. 进入 `域名管理与接入`。
3. 输入完整域名，例如 `example.com`。
4. 给这个主域名按上面的 Cloudflare 主域名接入方式添加 MX 和 A 记录。
5. 需要单独管理时，为该主域名生成 Token，然后访问 `/mail/example.com`。

## 删除子域名或其他主域名

1. 删除子域名：进入 `域名管理和接入`，点击目标子域名的 `删除子域名`，输入完整域名确认。
2. 删除其他主域名：使用全局管理员 Token，进入 `多主域名`，点击目标主域名的 `删除主域名`，按页面提示完成两步确认。
3. 删除前系统会自动创建备份；删除后对应域名的别名、邮件、附件、独立 Token 和接码链接都会失效。

## 独立接码链接

在别名卡片中生成并复制链接。链接只允许读取对应别名，可随时禁用或重置；重置后旧链接立即失效。导出的接码链接 TXT 应像密码文件一样保管。

## 程序对接

需要给其他程序取件时，下载 `API 文档`。最常用流程是：

1. `POST /ui-api/aliases` 创建或确认别名。
2. `GET /ui-api/changes` 长轮询等待新邮件。
3. `GET /ui-api/messages` 拉取邮件列表。
4. `GET /ui-api/message?id=邮件ID` 读取正文、验证码和链接。

管理员 Token 只应保存在受控服务端，不要写入公开网页、浏览器扩展或移动端安装包。出现 429 时应降低并发并退避重试。

## 收不到邮件时

依次检查云厂商 TCP 25 限制、服务器防火墙、SMTP 监听、Cloudflare MX、`mail` A 记录灰云状态、`PUBLIC_IP`、域名启用状态和配额。仅后台能打开不代表收件链路完成，必须从外部邮箱实际发送测试。
"""


# Current responsive panel template.
MAIL_REVIEW_HTML = r'''<!doctype html>
<html lang="zh-CN" data-visual="skyline">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="alternate icon" href="/favicon.ico" type="image/png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta name="theme-color" content="#38a7f3">
<title>__BRAND_TITLE__ · 收件箱</title>
<style>
:root{color-scheme:light;--bg:#f4f7fb;--panel:#fff;--panel2:#f8fafc;--panel3:#eef4ff;--text:#142033;--muted:#667085;--border:#d9e1ec;--accent:#2563eb;--accentText:#fff;--accent2:#0f9f6e;--danger:#dc2626;--dangerBg:#fff1f2;--dangerBorder:#fecdd3;--shadow:0 1px 2px rgba(16,24,40,.05)}
[data-theme=dark]{color-scheme:dark;--bg:#17191d;--panel:#1d2025;--panel2:#202329;--panel3:#282c33;--text:#eceef1;--muted:#a8adb6;--border:#3b4049;--accent:#d7d7d9;--accentText:#121214;--accent2:#b8b8bc;--danger:#f87171;--dangerBg:#351b1d;--dangerBorder:#8f3338;--shadow:none}
*{box-sizing:border-box}html,body{min-height:100%}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--text)}button,input,select{font:inherit}button{min-height:36px;border:1px solid var(--accent);background:var(--accent);color:var(--accentText);border-radius:7px;padding:0 11px;cursor:pointer;white-space:nowrap;transition:transform .12s ease,filter .12s ease,box-shadow .12s ease,opacity .12s ease}button:hover{filter:brightness(1.04)}button:active{transform:translateY(1px) scale(.99)}button.isBusy{position:relative;opacity:.78;cursor:progress}button.isBusy:after{content:"";width:12px;height:12px;border:2px solid currentColor;border-right-color:transparent;border-radius:999px;margin-left:8px;display:inline-block;vertical-align:-2px;animation:spin .8s linear infinite}button.secondary,a.secondary{background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:7px;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;min-height:34px;padding:0 10px}button.danger{background:var(--danger);border-color:var(--danger);color:#fff}button.softDanger{background:var(--dangerBg);border-color:var(--dangerBorder);color:var(--danger)}button:disabled,input:disabled,select:disabled{opacity:.55;cursor:not-allowed}input,select{width:100%;height:38px;border:1px solid var(--border);border-radius:7px;padding:0 10px;background:var(--panel);color:var(--text);min-width:0}.app{display:grid;grid-template-columns:minmax(340px,420px) minmax(0,1fr);height:100vh;overflow:hidden}.side{background:var(--panel);border-right:1px solid var(--border);padding:16px;display:flex;flex-direction:column;gap:12px;min-width:0;min-height:0;overflow:auto}.main{padding:16px;display:grid;grid-template-rows:auto minmax(0,1fr);gap:12px;min-width:0;min-height:0}.brand{font-size:20px;font-weight:750;word-break:break-all;line-height:1.25}.muted{color:var(--muted);font-size:13px}.box,.list,.detail{background:var(--panel);border:1px solid var(--border);border-radius:8px;box-shadow:var(--shadow)}.box{padding:12px}.sectionTitle{font-weight:750;font-size:13px;margin-bottom:8px}.row,.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.row input,.row select{flex:1}.compactGrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.generatorGrid{display:grid;grid-template-columns:1.1fr .8fr .8fr;gap:8px}.domains,.aliases{display:flex;flex-direction:column;gap:6px}.domain,.alias{border:1px solid var(--border);background:var(--panel2);border-radius:7px;padding:9px}.alias{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center}.aliasOpen{display:block;text-align:left;border:0;background:transparent;color:var(--text);padding:0;min-height:auto;white-space:normal}.aliasOpen:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.domain.active,.alias.active{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,var(--panel))}.email{font-weight:650;font-size:14px;word-break:break-all}.meta{font-size:12px;color:var(--muted);margin-top:4px}.dns{white-space:pre-wrap;background:var(--panel2);border:1px solid var(--border);border-radius:7px;padding:10px;font-size:12px;line-height:1.5;color:var(--text);margin-top:10px}.previewBox{background:var(--panel2);border:1px solid var(--border);border-radius:7px;padding:9px;font-size:12px;line-height:1.55;color:var(--text);max-height:150px;overflow:auto}.rulePreviewGrid{display:grid;grid-template-columns:1fr;gap:6px;margin-top:8px}.rulePreview{border:1px solid var(--border);border-radius:7px;padding:8px;background:var(--panel2)}.rulePreview b{font-size:12px}.rulePreview div{font-size:12px;color:var(--muted);word-break:break-all;margin-top:3px}.pager{display:grid;grid-template-columns:auto 1fr auto;gap:8px;align-items:center}.top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.topActions{justify-content:flex-end}.messages{display:grid;grid-template-columns:minmax(280px,380px) minmax(0,1fr);gap:12px;min-height:0}.list,.detail{overflow:auto}.mail{padding:12px;border-bottom:1px solid var(--border);cursor:pointer}.mail:hover{background:var(--panel2)}.mail.active{background:color-mix(in srgb,var(--accent) 10%,var(--panel))}.subject{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.preview{font-size:13px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:6px}.code{display:inline-flex;background:var(--accent2);color:#062016;border-radius:6px;padding:2px 7px;font-weight:800;margin-left:6px}.detail{padding:15px}.detail h2{font-size:20px;margin:0 0 10px;line-height:1.25}.detailHeader{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.actions{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.actions a{background:var(--accent);color:var(--accentText);text-decoration:none;border-radius:7px;padding:9px 12px;font-weight:650}.frame{width:100%;min-height:620px;border:1px solid var(--border);border-radius:8px;background:#fff}.err{color:var(--danger);font-size:13px;margin-top:6px}.pill{display:inline-flex;align-items:center;border:1px solid var(--border);background:var(--panel2);border-radius:999px;padding:5px 9px;font-size:12px;color:var(--muted)}.empty{padding:14px;color:var(--muted);font-size:13px}.dangerNote{color:var(--danger);font-weight:800}.fold{padding:0}.fold>summary{list-style:none;cursor:pointer;font-weight:750;font-size:13px;padding:12px}.fold>summary::-webkit-details-marker{display:none}.fold>summary:after{content:"展开";float:right;color:var(--muted);font-weight:650}.fold[open]>summary{border-bottom:1px solid var(--border)}.fold[open]>summary:after{content:"收起"}.foldBody{padding:12px}.hidden{display:none!important}.modal{position:fixed;inset:0;background:rgba(3,7,18,.58);display:flex;align-items:center;justify-content:center;padding:18px;z-index:50}.modalCard{width:min(520px,100%);background:var(--panel);border:2px solid var(--danger);border-radius:8px;box-shadow:0 20px 50px rgba(0,0,0,.25);padding:16px}.modalTitle{color:var(--danger);font-size:19px;font-weight:850;margin-bottom:8px}.modalText{white-space:pre-wrap;line-height:1.55;margin-bottom:12px}.modalInput{margin-bottom:12px;border-color:var(--danger)}.toastStack{position:fixed;right:18px;bottom:18px;z-index:90;display:flex;flex-direction:column;align-items:flex-end;gap:10px;max-width:min(380px,calc(100vw - 32px));pointer-events:none}.toast{pointer-events:auto;min-width:min(320px,calc(100vw - 32px));border:1px solid var(--border);background:color-mix(in srgb,var(--panel) 92%,#fff);color:var(--text);border-radius:8px;padding:11px 13px;box-shadow:0 16px 36px rgba(15,23,42,.18);font-size:13px;line-height:1.45;transform:translateY(10px);opacity:0;animation:toastIn .18s ease forwards}.toast.ok{border-color:color-mix(in srgb,var(--accent) 58%,var(--border))}.toast.err{border-color:var(--danger);color:var(--danger)}.toast.busy{border-color:color-mix(in srgb,var(--accent2) 55%,var(--border))}.toast b{display:block;margin-bottom:2px}@keyframes spin{to{transform:rotate(360deg)}}@keyframes toastIn{to{transform:translateY(0);opacity:1}}@keyframes toastOut{to{transform:translateY(8px);opacity:0}}
[data-visual=moyu]{--bg:#efe8d8;--panel:rgba(252,248,238,.94);--panel2:rgba(243,237,223,.92);--panel3:#e7dcc5;--text:#14241d;--muted:#647268;--border:#b9aa8d;--accent:#17634f;--accentText:#fbf7ec;--accent2:#1f8d6b;--danger:#b33a2f;--dangerBg:#f4ddd4;--dangerBorder:#ce8b75;--shadow:0 14px 30px rgba(52,42,24,.09)}
[data-theme=dark][data-visual=moyu]{--bg:#17191d;--panel:rgba(31,34,39,.96);--panel2:rgba(27,29,34,.94);--panel3:#2a2e35;--text:#eeeeef;--muted:#a8a8aa;--border:#4a4a4f;--accent:#d7d7d9;--accentText:#111112;--accent2:#bdbdc1;--danger:#e8766d;--dangerBg:#351d1c;--dangerBorder:#8f3f39;--shadow:0 18px 42px rgba(0,0,0,.28)}
[data-visual=moyu] body{background:radial-gradient(circle at 6% 8%,rgba(23,99,79,.12),transparent 24rem),radial-gradient(circle at 92% 18%,rgba(150,55,38,.10),transparent 20rem),linear-gradient(135deg,rgba(255,255,255,.22) 0,transparent 40%),var(--bg);font-family:Georgia,"Times New Roman","Noto Serif SC","Songti SC",system-ui,-apple-system,Segoe UI,sans-serif}
[data-visual=moyu] body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background:linear-gradient(90deg,rgba(20,36,29,.045) 1px,transparent 1px) 0 0/34px 34px,linear-gradient(0deg,rgba(20,36,29,.035) 1px,transparent 1px) 0 0/34px 34px,linear-gradient(90deg,transparent 0 74%,rgba(23,99,79,.13) 74.15% 74.75%,transparent 74.9% 100%) 0 0/168px 100%,linear-gradient(0deg,transparent 0 21%,rgba(23,99,79,.11) 21.2% 22.2%,transparent 22.5% 100%) 0 0/168px 96px,radial-gradient(ellipse at 72% 12%,rgba(23,99,79,.12) 0 7%,transparent 7.4% 100%) 0 0/230px 150px,radial-gradient(ellipse at 79% 20%,rgba(23,99,79,.10) 0 6%,transparent 6.4% 100%) 0 0/260px 190px,radial-gradient(circle at 22% 78%,rgba(23,99,79,.16),transparent 14rem),radial-gradient(circle at 80% 82%,rgba(179,58,47,.12),transparent 11rem);mix-blend-mode:multiply}
[data-theme=dark][data-visual=moyu] body:before{mix-blend-mode:screen;opacity:.42}
[data-visual=moyu] body:after{content:"墨玉文牍";position:fixed;right:18px;bottom:28px;z-index:0;color:rgba(23,99,79,.12);font-size:46px;font-weight:800;letter-spacing:.2em;writing-mode:vertical-rl;pointer-events:none;text-shadow:0 1px 0 rgba(255,255,255,.38)}
[data-theme=dark][data-visual=moyu] body:after{color:rgba(134,199,173,.12);text-shadow:none}
[data-visual=moyu] .main{position:relative;overflow:hidden}
[data-visual=moyu] .main>*{position:relative;z-index:2}
[data-visual=moyu] .main:before{content:"";position:fixed;right:2.5vw;top:6vh;width:330px;height:86vh;pointer-events:none;z-index:1;opacity:.34;background:linear-gradient(90deg,transparent 0 17%,rgba(16,79,61,.42) 17.4% 18.8%,rgba(250,247,236,.23) 19% 19.5%,transparent 19.8% 100%),linear-gradient(90deg,transparent 0 41%,rgba(16,79,61,.35) 41.4% 42.8%,rgba(250,247,236,.18) 43% 43.4%,transparent 43.8% 100%),linear-gradient(90deg,transparent 0 65%,rgba(16,79,61,.28) 65.4% 66.7%,transparent 67% 100%),linear-gradient(0deg,transparent 0 11%,rgba(16,79,61,.20) 11.2% 12.1%,transparent 12.5% 23%,rgba(16,79,61,.18) 23.3% 24.2%,transparent 24.5% 38%,rgba(16,79,61,.15) 38.3% 39.2%,transparent 39.5% 54%,rgba(16,79,61,.15) 54.3% 55.2%,transparent 55.5% 72%,rgba(16,79,61,.16) 72.3% 73.2%,transparent 73.6% 100%),radial-gradient(ellipse at 23% 18%,rgba(16,79,61,.34) 0 7%,transparent 7.5% 100%),radial-gradient(ellipse at 30% 24%,rgba(16,79,61,.28) 0 6%,transparent 6.5% 100%),radial-gradient(ellipse at 47% 38%,rgba(16,79,61,.30) 0 7%,transparent 7.5% 100%),radial-gradient(ellipse at 55% 44%,rgba(16,79,61,.24) 0 6%,transparent 6.5% 100%),radial-gradient(ellipse at 71% 66%,rgba(16,79,61,.24) 0 6%,transparent 6.6% 100%);filter:blur(.15px)}
[data-visual=moyu] .main:after{content:"";position:fixed;left:43%;top:2.6vh;width:34vw;height:82px;pointer-events:none;z-index:1;opacity:.28;background:radial-gradient(ellipse at 12% 60%,rgba(179,58,47,.26) 0 7%,transparent 7.6%),radial-gradient(ellipse at 26% 48%,rgba(23,99,79,.22) 0 8%,transparent 8.6%),radial-gradient(ellipse at 44% 56%,rgba(179,58,47,.18) 0 7%,transparent 7.6%),radial-gradient(ellipse at 62% 50%,rgba(23,99,79,.18) 0 8%,transparent 8.6%),linear-gradient(90deg,transparent,rgba(23,99,79,.26),transparent);border-bottom:1px solid rgba(23,99,79,.16)}
[data-visual=moyu] .app:before{content:"";position:fixed;left:424px;top:18px;bottom:18px;width:12px;pointer-events:none;z-index:2;background:linear-gradient(180deg,transparent,rgba(23,99,79,.36),transparent),repeating-linear-gradient(180deg,rgba(179,58,47,.34) 0 8px,transparent 8px 18px);border-radius:999px;opacity:.45}
[data-visual=moyu] .app:after{content:"飞鸿传书";position:fixed;left:438px;bottom:24px;z-index:2;color:rgba(179,58,47,.22);font-size:13px;letter-spacing:.18em;writing-mode:vertical-rl;pointer-events:none}
[data-visual=moyu] .app{position:relative;z-index:1;border:10px solid transparent;border-image:linear-gradient(135deg,rgba(23,99,79,.55),rgba(185,170,141,.32),rgba(179,58,47,.38)) 1;background:rgba(255,252,244,.28)}
[data-visual=moyu] .side{position:relative;border-right:1px solid color-mix(in srgb,var(--border) 75%,var(--accent));background:linear-gradient(180deg,rgba(252,248,238,.98),rgba(239,232,216,.93));box-shadow:inset -10px 0 22px rgba(42,32,17,.04)}
[data-theme=dark][data-visual=moyu] .side{background:linear-gradient(180deg,rgba(22,31,27,.98),rgba(15,24,21,.94))}
[data-visual=moyu] .side:before{content:"邮";position:absolute;right:17px;top:18px;width:38px;height:38px;border:2px solid var(--danger);color:var(--danger);display:grid;place-items:center;font-weight:900;transform:rotate(-8deg);border-radius:3px;background:color-mix(in srgb,var(--dangerBg) 70%,transparent)}
[data-visual=moyu] .side>div:first-child{padding:9px 54px 14px 0;border-bottom:1px solid color-mix(in srgb,var(--border) 70%,transparent);position:relative}
[data-visual=moyu] .side>div:first-child:after{content:"信札入匣 · 验码归卷";display:block;margin-top:8px;color:var(--accent);font-size:12px;letter-spacing:.12em}
[data-visual=moyu] .brand{font-family:Georgia,"Noto Serif SC","Songti SC",serif;letter-spacing:.02em}
[data-visual=moyu] .box,[data-visual=moyu] .list,[data-visual=moyu] .detail{position:relative;border-color:color-mix(in srgb,var(--border) 82%,var(--accent));background:linear-gradient(180deg,var(--panel),color-mix(in srgb,var(--panel2) 45%,var(--panel)));box-shadow:var(--shadow),inset 0 0 0 1px rgba(255,255,255,.38)}
[data-visual=moyu] .box:before,[data-visual=moyu] .list:before,[data-visual=moyu] .detail:before{content:"";position:absolute;left:7px;top:7px;width:18px;height:18px;border-left:2px solid color-mix(in srgb,var(--accent) 70%,transparent);border-top:2px solid color-mix(in srgb,var(--accent) 70%,transparent);opacity:.7;pointer-events:none}
[data-visual=moyu] .box:after,[data-visual=moyu] .list:after,[data-visual=moyu] .detail:after{content:"";position:absolute;right:7px;bottom:7px;width:18px;height:18px;border-right:2px solid color-mix(in srgb,var(--danger) 58%,transparent);border-bottom:2px solid color-mix(in srgb,var(--danger) 58%,transparent);opacity:.55;pointer-events:none}
[data-visual=moyu] .sectionTitle{color:var(--accent);letter-spacing:.08em}
[data-visual=moyu] .sectionTitle:before{content:"◆";margin-right:6px;color:var(--danger);font-size:10px}
[data-visual=moyu] input,[data-visual=moyu] select{border-color:color-mix(in srgb,var(--border) 80%,var(--accent));background:color-mix(in srgb,var(--panel) 84%,#fff)}
[data-theme=dark][data-visual=moyu] input,[data-theme=dark][data-visual=moyu] select{background:color-mix(in srgb,var(--panel) 86%,#000)}
[data-visual=moyu] button{box-shadow:0 1px 0 rgba(255,255,255,.28) inset}
[data-visual=moyu] button.secondary,[data-visual=moyu] a.secondary{background:linear-gradient(180deg,var(--panel),var(--panel2));border-color:color-mix(in srgb,var(--border) 80%,var(--accent))}
[data-visual=moyu] .top{padding:13px 14px;border:1px solid color-mix(in srgb,var(--border) 78%,var(--accent));background:linear-gradient(90deg,var(--panel),color-mix(in srgb,var(--panel3) 34%,var(--panel)));border-radius:8px;box-shadow:var(--shadow);position:relative}
[data-visual=moyu] .top:before{content:"";position:absolute;inset:5px;border:1px solid rgba(23,99,79,.18);border-radius:5px;pointer-events:none}
[data-visual=moyu] .pill{border-color:color-mix(in srgb,var(--accent) 52%,var(--border));color:var(--accent);background:color-mix(in srgb,var(--panel3) 58%,var(--panel));font-weight:750}
[data-visual=moyu] .domain,[data-visual=moyu] .alias,[data-visual=moyu] .mail{background:linear-gradient(180deg,var(--panel2),color-mix(in srgb,var(--panel) 42%,var(--panel2)));border-color:color-mix(in srgb,var(--border) 82%,transparent)}
[data-visual=moyu] .domain.active,[data-visual=moyu] .alias.active,[data-visual=moyu] .mail.active{background:linear-gradient(90deg,color-mix(in srgb,var(--accent) 16%,var(--panel)),var(--panel));border-color:var(--accent)}
[data-visual=moyu] .code{background:linear-gradient(180deg,#2d9d79,var(--accent));color:#f8fff8;border:1px solid color-mix(in srgb,var(--accent) 70%,#fff);letter-spacing:.06em}
[data-visual=moyu] .danger,[data-visual=moyu] button.danger{background:linear-gradient(180deg,#c64c3c,var(--danger));border-color:#8e241f;color:#fff}
[data-visual=moyu] .softDanger{background:color-mix(in srgb,var(--dangerBg) 82%,var(--panel));border-color:var(--dangerBorder)}
[data-visual=moyu] .fold>summary{background:linear-gradient(90deg,color-mix(in srgb,var(--panel3) 45%,var(--panel)),transparent);color:var(--accent);letter-spacing:.06em}
[data-visual=moyu] .dns,[data-visual=moyu] .previewBox,[data-visual=moyu] .rulePreview{background:color-mix(in srgb,var(--panel2) 86%,var(--panel));border-style:dashed}
[data-visual=moyu] .modalCard{border-color:var(--danger);background:linear-gradient(180deg,var(--panel),var(--panel2))}
[data-theme=dark][data-visual=moyu] body{background:radial-gradient(circle at 8% 8%,rgba(255,255,255,.045),transparent 23rem),radial-gradient(circle at 92% 18%,rgba(255,255,255,.035),transparent 20rem),linear-gradient(135deg,rgba(255,255,255,.035) 0,transparent 42%),var(--bg)}
[data-theme=dark][data-visual=moyu] body:before{filter:grayscale(1);opacity:.24;mix-blend-mode:screen}
[data-theme=dark][data-visual=moyu] body:after{color:rgba(220,220,224,.10);text-shadow:none}
[data-theme=dark][data-visual=moyu] .main:before,[data-theme=dark][data-visual=moyu] .main:after,[data-theme=dark][data-visual=moyu] .app:before,[data-theme=dark][data-visual=moyu] .app:after{filter:grayscale(1);opacity:.22}
[data-theme=dark][data-visual=moyu] .app{border-image:linear-gradient(135deg,rgba(220,220,224,.38),rgba(128,128,132,.24),rgba(220,220,224,.20)) 1;background:rgba(18,18,19,.42)}
[data-theme=dark][data-visual=moyu] .side{background:linear-gradient(180deg,rgba(29,29,31,.98),rgba(18,18,20,.96));box-shadow:inset -10px 0 22px rgba(0,0,0,.16)}
[data-theme=dark][data-visual=moyu] .top:before{border-color:rgba(220,220,224,.16)}
[data-theme=dark][data-visual=moyu] .code{background:linear-gradient(180deg,#dadadd,#a9a9ad);color:#111;border-color:#5f5f64}
[data-theme=dark][data-visual=moyu] button:not(.secondary):not(.danger):not(.softDanger){background:linear-gradient(180deg,#e1e1e3,#bebec2);border-color:#d7d7d9;color:#111112}
[data-visual=minimal] body:before,[data-visual=minimal] body:after{display:none}
@media(max-width:980px){.app{display:block;height:auto;min-height:100vh;overflow:visible}.side{border-right:0;border-bottom:1px solid var(--border);max-height:none;overflow:visible}.main{display:block;padding:12px}.top{flex-direction:column}.topActions{width:100%}.messages{grid-template-columns:1fr}.list{max-height:45vh}.detail{margin-top:12px}.frame{min-height:520px}[data-visual=moyu] .app{border-width:6px}[data-visual=moyu] body:after{display:none}}@media(max-width:560px){.side{padding:12px}.box{padding:11px}.fold{padding:0}.fold>summary,.foldBody{padding:11px}.row,.toolbar{align-items:stretch}.row>button,.toolbar>button,.toolbar>a{flex:1}.topActions{display:grid;grid-template-columns:1fr 1fr;width:100%;align-items:stretch}.topActions .pill,.topActions #clearDomainMail{grid-column:1/-1}.topActions button,.topActions a.secondary{width:100%;min-width:0;white-space:normal;line-height:1.2;padding:7px 8px}.compactGrid,.generatorGrid{grid-template-columns:1fr}.pager{grid-template-columns:1fr}.alias{grid-template-columns:1fr}.alias .softDanger{width:100%}.detailHeader{flex-direction:column}.detailHeader .toolbar{width:100%}.detailHeader .toolbar button{flex:1}.brand{font-size:18px}.messages{gap:10px}.list{max-height:52vh}.modal{align-items:flex-end;padding:0}.modalCard{border-radius:8px 8px 0 0;width:100%;padding:14px}.frame{min-height:460px}[data-visual=moyu] .side:before{right:12px;top:12px;width:32px;height:32px}}
</style>
<style>
.main{grid-template-rows:auto auto minmax(0,1fr)}.mailTools{padding:10px;display:grid;gap:8px}.filterGrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.checkLine{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--muted);white-space:nowrap}.checkLine input,.mailCheck{width:16px;height:16px;accent-color:var(--accent)}.mail{display:grid;grid-template-columns:auto minmax(0,1fr);gap:9px;align-items:start}.mail.unread .subject{font-weight:850}.mailFlags{display:flex;gap:5px;flex-wrap:wrap;margin-top:6px}.flag{font-size:11px;border:1px solid var(--border);border-radius:999px;padding:2px 6px;color:var(--muted);background:var(--panel)}.flag.hot{color:var(--danger);border-color:var(--dangerBorder);background:var(--dangerBg)}.mailMetaLine{min-width:0}.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:12px 0}.tabBtn.active{background:var(--accent);color:var(--accentText);border-color:var(--accent)}.plainView{white-space:pre-wrap;line-height:1.55;border:1px solid var(--border);background:var(--panel2);border-radius:8px;padding:12px;overflow:auto;max-height:620px}.attachList{display:grid;gap:6px;margin:10px 0}.attach{display:flex;justify-content:space-between;gap:8px;align-items:center;border:1px solid var(--border);border-radius:7px;padding:8px;background:var(--panel2)}.statsGrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.stat{border:1px solid var(--border);border-radius:7px;background:var(--panel2);padding:9px}.stat b{display:block;font-size:18px}.domainCard{display:grid;gap:8px}.domainForm{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.domainForm input{height:34px;font-size:13px}.logBox{max-height:220px;overflow:auto;border:1px solid var(--border);border-radius:7px;background:var(--panel2);padding:8px;font-size:12px;line-height:1.45}.statusList{display:grid;gap:6px}.statusItem{border:1px solid var(--border);border-radius:7px;padding:8px;background:var(--panel2)}.statusItem.ok{border-color:color-mix(in srgb,var(--accent) 55%,var(--border))}.statusItem.bad{border-color:var(--danger);color:var(--danger)}.rightMini{margin-left:auto}.mailPager{display:grid;grid-template-columns:auto 1fr auto;gap:8px;align-items:center}.copyTokenLine{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;word-break:break-all;color:var(--muted)}.aliasActions{justify-content:flex-end}.aliasActions button{min-height:32px;padding:0 8px;font-size:12px}.shareState{display:inline-flex;margin-left:5px;color:var(--accent);font-weight:750}.docButton{font-weight:750;border-color:color-mix(in srgb,var(--accent) 55%,var(--border))!important}.livePill{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 60%,var(--border));background:color-mix(in srgb,var(--panel3) 70%,var(--panel));font-weight:750}@media(max-width:760px){.filterGrid,.domainForm,.statsGrid{grid-template-columns:1fr}.mailTools .toolbar button,.mailTools .toolbar select{flex:1}.mail{grid-template-columns:auto minmax(0,1fr)}.mailPager{grid-template-columns:1fr}.attach{display:block}.attach .toolbar{margin-top:8px}.detail h2{font-size:18px}}
</style>
<style>
.app{grid-template-columns:minmax(420px,500px) minmax(0,1fr)}
[data-visual=moyu] .app:before{left:504px}
[data-visual=moyu] .app:after{left:518px}
.mailTools{padding:0;display:block}
.mailTools>.foldBody{display:grid;gap:8px}
.monitorBox{display:grid;gap:8px}
.monitorItem{border:1px solid var(--border);border-radius:7px;padding:8px;background:var(--panel2);line-height:1.45}
.monitorItem.ok,.statusItem.ok{border-color:color-mix(in srgb,var(--accent) 55%,var(--border))}
.monitorItem.bad,.statusItem.bad{border-color:var(--danger);color:var(--danger);background:color-mix(in srgb,var(--dangerBg) 70%,var(--panel2))}
.monitorItem.warn,.statusItem.warn{border-color:color-mix(in srgb,#d97706 68%,var(--border));color:#92400e;background:color-mix(in srgb,#f59e0b 12%,var(--panel2))}
.monitorIcon,.statusIcon{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:999px;margin-right:6px;font-weight:900;font-size:12px;line-height:1;background:var(--panel3);border:1px solid currentColor;vertical-align:middle}
.statusIcon.ok,.monitorIcon.ok{color:var(--accent)}
.statusIcon.bad,.monitorIcon.bad{color:var(--danger)}
.statusIcon.warn,.monitorIcon.warn{color:#92400e}
.statusTitle{display:flex;align-items:center;gap:0;flex-wrap:wrap;font-weight:850}
.toastStack{max-width:min(520px,calc(100vw - 32px))}
.toast.dnsResult{min-width:min(500px,calc(100vw - 32px));border-width:2px;border-left-width:9px;padding:17px 18px;font-size:18px;font-weight:750;line-height:1.35;box-shadow:0 22px 54px rgba(15,23,42,.28)}
.toast.dnsResult b{font-size:21px;margin-bottom:5px}
.toast.dnsResult div{font-weight:650}
.domainAddGrid{display:grid;gap:10px}
.domainAddGroup{display:grid;gap:6px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.domainAddGroup:last-child{padding-bottom:0;border-bottom:0}
.domainAddTitle{font-weight:750;font-size:13px}
.domainAddHelp{font-size:12px;color:var(--muted);line-height:1.45}
.accessStatus{display:grid;gap:6px;margin-bottom:6px}
.accessCard{border:1px solid var(--border);border-radius:8px;padding:6px 8px;background:var(--panel2);display:flex;align-items:center;gap:5px 8px;flex-wrap:wrap}
.accessCard.ok{border-color:color-mix(in srgb,var(--accent2) 68%,var(--border));background:color-mix(in srgb,var(--accent2) 12%,var(--panel))}
.accessCard.wait{border-color:color-mix(in srgb,#d97706 60%,var(--border));background:color-mix(in srgb,#f59e0b 14%,var(--panel))}
.accessMain{display:flex;align-items:center;gap:7px;flex-wrap:wrap;min-width:190px;flex:1 1 220px}
.accessTitle{font-size:13px;font-weight:850}
.accessBadge{display:inline-flex;align-items:center;border-radius:999px;padding:3px 7px;font-size:12px;font-weight:800;white-space:nowrap}
.accessCard.ok .accessBadge{background:color-mix(in srgb,var(--accent2) 22%,var(--panel));color:var(--accent)}
.accessCard.wait .accessBadge{background:color-mix(in srgb,#f59e0b 22%,var(--panel));color:#92400e}
.accessSteps{display:flex;align-items:center;gap:7px;flex-wrap:wrap;color:var(--muted)}
.accessStep{display:inline-flex;align-items:center;border:0;border-radius:0;padding:0;background:transparent;font-size:11px;line-height:1.1;white-space:nowrap}
.accessStep.done{color:var(--accent)}
.accessStep.todo{color:#92400e}
.accessStep.bad{color:var(--danger)}
.accessToolbar{margin-left:auto;gap:5px}
.accessToolbar button{min-height:26px;padding:0 8px;font-size:12px}
.guideHiddenByStatus{display:none!important}
.cloudflareGuideBox{position:relative;z-index:5;padding:0;border:2px solid color-mix(in srgb,var(--accent) 72%,var(--border));background:linear-gradient(180deg,color-mix(in srgb,var(--panel3) 58%,var(--panel)),var(--panel));box-shadow:0 14px 34px rgba(15,23,42,.12);overflow:visible}
.cloudflareGuideSummary{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 12px;font-weight:850;list-style:none;border-bottom:1px solid var(--border)}
.cloudflareGuideSummary::-webkit-details-marker{display:none}
.cloudflareGuideHeaderActions{margin-left:auto;gap:6px}
.cloudflareGuideHeaderActions button{min-height:28px;padding:0 8px;font-size:12px}
.cloudflareGuideBody{position:relative;padding:10px 12px 12px;display:grid;gap:8px}
.cloudflareGuideBox.guideBodyCollapsed .cloudflareGuideBody{display:none}
.guideActions{position:relative;z-index:2;justify-content:flex-end}
#hideCloudflareGuide{position:relative;z-index:3;pointer-events:auto}
.cloudflareGuideDomain{display:inline-flex;margin-bottom:8px;border:1px solid color-mix(in srgb,var(--accent) 55%,var(--border));border-radius:999px;padding:5px 9px;background:var(--panel);color:var(--accent);font-size:12px;font-weight:750;word-break:break-all}
.cloudflareGuideHelp{font-size:12px;color:var(--muted);line-height:1.5}
.cloudflareGuide{margin-top:8px;border:1px solid color-mix(in srgb,var(--accent) 64%,var(--border));background:color-mix(in srgb,var(--panel) 72%,var(--panel3));font-size:13px}
#rootTabs .tabBtn,#rootTabs .tabBtn:visited{background:var(--panel)!important;color:#14171a!important;border-color:color-mix(in srgb,var(--border) 78%,#14171a)!important;opacity:1!important}
#rootTabs .tabBtn.active,#rootTabs .tabBtn.active:visited{background:#e7dcc5!important;color:#111112!important;border-color:#8a7a5f!important;box-shadow:inset 0 0 0 1px rgba(255,255,255,.5)!important;opacity:1!important}
[data-theme=dark] #rootTabs .tabBtn,[data-theme=dark] #rootTabs .tabBtn:visited{background:#eeeeef!important;color:#111112!important;border-color:#76767a!important}
[data-theme=dark] #rootTabs .tabBtn.active,[data-theme=dark] #rootTabs .tabBtn.active:visited{background:#d7d7d9!important;color:#111112!important;border-color:#a8a8aa!important}
#overviewStats{grid-template-columns:repeat(auto-fit,minmax(92px,1fr));gap:6px}
#overviewStats .stat{min-height:34px;padding:6px 8px;display:flex;align-items:center;justify-content:space-between;gap:6px}
#overviewStats .stat b{display:inline;font-size:15px}
#overviewStats .stat .muted{font-size:12px;white-space:nowrap}
.aliasListHead{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px}
.aliasToolsFold{margin:0 0 8px}
.domainStatsFold{margin-top:10px;border:1px solid var(--border);border-radius:7px;background:var(--panel2)}
.domainStatsFold>summary{padding:9px 10px;font-size:12px;font-weight:750;cursor:pointer;list-style:none}
.domainStatsFold>summary::-webkit-details-marker{display:none}
.domainStatsFold>summary:after{content:"展开";float:right;color:var(--muted)}
.domainStatsFold[open]>summary{border-bottom:1px solid var(--border)}
.domainStatsFold[open]>summary:after{content:"收起"}
.domainStatsBody{padding:8px;display:grid;gap:6px}
.adminNav{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0 10px}
.adminNav button{min-height:32px;padding:0 9px;font-size:12px}
.adminNav button.active{background:var(--accent);color:var(--accentText);border-color:var(--accent)}
.adminPanelSection.hidden{display:none!important}
.rootTokenList{display:grid;gap:6px}
.rootTokenCard{display:grid;gap:8px}
.tableWrap{overflow:auto;border:1px solid var(--border);border-radius:7px;background:var(--panel2)}
.adminTable{width:100%;border-collapse:collapse;font-size:12px;min-width:760px}
.adminTable th,.adminTable td{padding:8px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
.adminTable th{color:var(--muted);font-weight:750;background:var(--panel)}
.adminTable tr:last-child td{border-bottom:0}
.adminTable .toolbar{gap:5px}.adminTable button,.adminTable a.secondary{min-height:28px;padding:0 7px;font-size:12px}
.batchArea{width:100%;min-height:92px;border:1px solid var(--border);border-radius:7px;padding:8px;background:var(--panel);color:var(--text);resize:vertical}
.settingsGroup{grid-column:1/-1;border:1px solid var(--border);border-radius:7px;padding:8px;background:var(--panel2);display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}
.settingsGroupTitle{grid-column:1/-1;color:var(--accent);font-weight:750;font-size:12px}
.domainSettings{border:1px solid var(--border);border-radius:7px;background:var(--panel2)}
.domainSettings>.foldBody{background:var(--panel);border-radius:0 0 7px 7px}
.webhookHint{grid-column:1/-1;color:var(--muted);font-size:12px;line-height:1.45}
.deleteClearBox{border:1px solid var(--dangerBorder);border-radius:8px;background:color-mix(in srgb,var(--dangerBg) 72%,var(--panel));margin-top:8px}
.deleteClearBox>summary{list-style:none;cursor:pointer;font-weight:800;color:var(--danger);padding:10px 11px;font-size:13px}
.deleteClearBox>summary::-webkit-details-marker{display:none}
.deleteClearBox>summary:after{content:"展开";float:right;color:var(--danger);font-weight:750}
.deleteClearBox[open]>summary{border-bottom:1px solid var(--dangerBorder)}
.deleteClearBox[open]>summary:after{content:"收起"}
.deleteClearBody{padding:10px;display:grid;gap:7px}
@media(max-width:980px){.app{grid-template-columns:1fr}[data-visual=moyu] .app:before,[data-visual=moyu] .app:after{display:none}}
@media(max-width:760px){.settingsGroup,.accessSteps{grid-template-columns:1fr}.adminTable{min-width:680px}}
@media(max-width:760px){#overviewStats{grid-template-columns:repeat(2,minmax(0,1fr))}.accessToolbar{margin-left:0;width:100%}.accessToolbar button{flex:1}.cloudflareGuideSummary{align-items:flex-start}.guideActions button{flex:1}}
</style>
<style>__TENANT_STYLE__</style>
<style>
.codeQuickBtn{min-height:auto;border:0;cursor:pointer;line-height:1.3;vertical-align:baseline}
.codeQuickBtn:hover{filter:brightness(1.08)}
.codeQuickBtn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
</style>
<style>
:root{--bg:#f5f7fa;--panel:#fff;--panel2:#f8fafc;--panel3:#eef4ff;--text:#172033;--muted:#647084;--border:#dce2ea;--accent:#2563eb;--accentText:#fff;--accent2:#0f766e;--danger:#c62828;--dangerBg:#fff5f5;--dangerBorder:#f3c5c5;--shadow:0 8px 24px rgba(15,23,42,.06)}
[data-theme=dark]{--bg:#17191d;--panel:#1d2025;--panel2:#22262d;--panel3:#292e37;--text:#edf1f7;--muted:#a3aab5;--border:#3a404a;--accent:#77a6ff;--accentText:#0d1728;--accent2:#5dd2bd;--danger:#ff8a8a;--dangerBg:#321e22;--dangerBorder:#71383e;--shadow:none}
html,body{height:100%;overflow:hidden}body{background:var(--bg)!important;font-family:Inter,"Segoe UI",system-ui,-apple-system,sans-serif!important;color:var(--text)}body:before,body:after,.app:before,.app:after,.main:before,.main:after,.side:before,.side>div:first-child:after{display:none!important}
button,input,select,textarea{font:inherit}button{min-height:36px;border-radius:7px;padding:0 12px;font-weight:650;box-shadow:none!important;transition:border-color .15s ease,background .15s ease,opacity .15s ease,transform .1s ease}button:hover{filter:none;background:color-mix(in srgb,var(--accent) 90%,#000)}button.secondary,a.secondary{background:var(--panel);border-color:var(--border);color:var(--text);font-weight:600}button.secondary:hover,a.secondary:hover{background:var(--panel2);border-color:color-mix(in srgb,var(--accent) 42%,var(--border))}input,select,textarea{border-radius:7px;background:var(--panel);border-color:var(--border)}input:focus,select:focus,textarea:focus{outline:2px solid color-mix(in srgb,var(--accent) 22%,transparent);border-color:var(--accent)}
.app{height:100vh;display:grid!important;grid-template-columns:320px minmax(0,1fr)!important;border:0!important;background:var(--bg)!important;overflow:hidden}.side{padding:18px 14px!important;gap:12px;background:var(--panel)!important;border-right:1px solid var(--border)!important;box-shadow:none!important;overflow:auto}.side>div:first-child{padding:2px 2px 8px!important;border:0!important}.side .brand{font-family:inherit!important;font-size:18px;letter-spacing:0!important}.main{padding:18px!important;gap:12px;grid-template-rows:auto auto minmax(0,1fr)!important;overflow:hidden!important;background:var(--bg)}
.box,.list,.detail,.top{background:var(--panel)!important;border:1px solid var(--border)!important;border-radius:10px!important;box-shadow:var(--shadow)!important}.box:before,.box:after,.list:before,.list:after,.detail:before,.detail:after,.top:before{display:none!important}.box{padding:12px}.sectionTitle{margin:0 0 9px;color:var(--text)!important;font-size:12px;letter-spacing:.02em!important;text-transform:none}.sectionTitle:before{display:none!important}.muted{color:var(--muted);line-height:1.45}.top{padding:14px 16px!important;align-items:center}.top .brand{font-size:19px;line-height:1.25}.topActions{align-items:center;gap:7px}.livePill{border:0!important;background:transparent!important;padding:0 4px;color:var(--accent2)!important}.livePill:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;margin-right:6px;box-shadow:0 0 0 3px color-mix(in srgb,currentColor 15%,transparent)}
.livePill[data-state="syncing"]{color:var(--accent)!important}.livePill[data-state="error"],.livePill[data-state="offline"]{color:var(--danger)!important}.livePill[data-state="idle"]{color:var(--muted)!important}
#loginBox{transition:opacity .15s ease}.isAuthed #loginBox{display:none}body:not(.isAuthed) .app{grid-template-columns:minmax(300px,420px)!important;place-content:start center;padding:10vh 16px}body:not(.isAuthed) .side{width:100%;max-height:none;border:1px solid var(--border)!important;border-radius:12px;padding:20px!important;box-shadow:var(--shadow)!important}body:not(.isAuthed) .side>:not(.sidebarBrand):not(#loginBox):not(.sidebarFooter){display:none!important}body:not(.isAuthed) .sidebarFooter>#refreshAll,body:not(.isAuthed) .sidebarFooter>#clearToken{display:none!important}body:not(.isAuthed) .main{display:none!important}.adminLauncher{display:grid;grid-template-columns:1fr;gap:6px}.adminLauncher button{width:100%}.aliasListHead{margin-bottom:7px}.aliases{gap:5px}.alias{display:block!important;padding:8px 9px!important;border-radius:8px!important;background:var(--panel2)!important}.alias.active{background:var(--panel3)!important;border-color:color-mix(in srgb,var(--accent) 55%,var(--border))!important}.aliasOpen{width:100%;min-width:0}.alias .email{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;word-break:normal}.aliasActions{gap:4px;justify-content:flex-start;margin-top:7px}.aliasActions button{min-height:28px;padding:0 7px}.email{font-size:13px}.meta{margin-top:2px}.fold>summary,.domainStatsFold>summary{color:var(--text)!important;background:transparent!important;letter-spacing:0!important}.fold>summary:after,.domainStatsFold>summary:after{font-weight:500}.deleteClearBox{background:var(--dangerBg);border-color:var(--dangerBorder)}
.mailTools{padding:0!important}.mailTools>summary{padding:10px 13px}.mailTools>.foldBody{padding:12px}.filterGrid{grid-template-columns:repeat(3,minmax(0,1fr))}.messages{grid-template-columns:minmax(300px,360px) minmax(0,1fr);gap:12px;min-height:0}.list,.detail{min-height:0;overflow:auto}.mail{padding:12px 13px;gap:9px;background:var(--panel)!important}.mail:hover{background:var(--panel2)!important}.mail.active{background:var(--panel3)!important;border-left:3px solid var(--accent)}.mail .subject{font-size:14px}.mail .preview{margin-top:4px;font-size:12px}.mailFlags{margin-top:5px}.flag{padding:1px 6px;background:transparent}.code{margin-left:5px;border:0!important;border-radius:6px;background:color-mix(in srgb,var(--accent2) 15%,var(--panel))!important;color:var(--accent2)!important;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.03em}.detail{padding:18px;overflow-anchor:none}.detailHeader{position:sticky;top:-18px;z-index:8;margin:-18px -18px 0;padding:18px 18px 13px;border-bottom:1px solid var(--border);background:var(--panel)}.detailHeader .toolbar{justify-content:flex-end}.detail h2{font-size:19px}.frame{min-height:520px;border-radius:7px}.plainView{max-height:none}.empty{padding:18px;line-height:1.55}.toast{border-radius:8px}.toast.dnsResult{font-size:14px;min-width:min(380px,calc(100vw - 32px));border-left-width:5px;padding:13px 14px}.toast.dnsResult b{font-size:15px}
.quickMenu{position:relative}.quickMenu>summary{display:flex;align-items:center;min-height:36px;padding:0 12px;list-style:none;cursor:pointer;border:1px solid var(--border);border-radius:7px;background:var(--panel);color:var(--text);font-weight:600}.quickMenu>summary:hover{background:var(--panel2);border-color:color-mix(in srgb,var(--accent) 42%,var(--border))}.quickMenu>summary::-webkit-details-marker{display:none}.quickMenuPanel{position:absolute;right:0;top:calc(100% + 7px);z-index:25;width:190px;padding:7px;display:grid;gap:5px;border:1px solid var(--border);border-radius:8px;background:var(--panel);box-shadow:0 16px 36px rgba(15,23,42,.16)}.quickMenuPanel>*{width:100%;justify-content:flex-start}.sidebarFooter{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}.sidebarFooter>*{min-width:0;justify-content:center;text-align:center}
.adminDrawer{position:fixed!important;inset:0;z-index:70;display:grid!important;grid-template-columns:minmax(220px,1fr) minmax(620px,900px);background:transparent}.adminDrawer.drawerClosed{display:none!important}.adminDrawerBackdrop{position:absolute;inset:0;width:100%;height:100%;border:0;border-radius:0;background:rgba(15,23,42,.46)!important;cursor:default}.adminSheet{position:relative;grid-column:2;height:100%;overflow:auto;background:var(--bg);border-left:1px solid var(--border);box-shadow:-18px 0 50px rgba(15,23,42,.18);padding:18px;z-index:1}.adminDrawerHeader{position:sticky;top:-18px;z-index:10;display:flex;align-items:center;justify-content:space-between;gap:12px;margin:-18px -18px 12px;padding:16px 18px;background:color-mix(in srgb,var(--panel) 94%,transparent);border-bottom:1px solid var(--border);backdrop-filter:blur(12px)}.adminDrawerTitle{font-size:18px;font-weight:800}.adminSheet .adminNav{margin:0 0 12px;padding:7px;border:1px solid var(--border);border-radius:9px;background:var(--panel);position:sticky;top:55px;z-index:9}.adminSheet .adminPanelSection,.adminSheet .cloudflareGuideBox{margin-top:12px}.adminSheet .box{box-shadow:none!important}.adminTable{min-width:720px}
body.adminOpen{overflow:hidden}.statusItem,.monitorItem,.accessCard,.stat{border-radius:7px!important}.accessCard{padding:9px 10px}.cloudflareGuideBox{border-width:1px!important}.cloudflareGuideHelp,.domainAddHelp{max-width:72ch}.modalCard{border-width:1px;border-radius:10px}.modalTitle{font-size:17px}.modalText{font-size:14px}
@media(max-width:1080px){.app{grid-template-columns:290px minmax(0,1fr)!important}.messages{grid-template-columns:minmax(280px,330px) minmax(0,1fr)}.topActions .optionalAction{display:none}.filterGrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:820px){html,body{height:auto;overflow:auto}.app{display:block!important;height:auto;min-height:100vh;overflow:visible}.side{border-right:0!important;border-bottom:1px solid var(--border)!important;max-height:46vh;overflow:auto}.main{display:grid!important;min-height:100vh;overflow:visible!important}.top{align-items:flex-start}.topActions{width:100%;justify-content:flex-start}.messages{grid-template-columns:1fr}.list{max-height:42vh}.detail{min-height:52vh}.adminDrawer{grid-template-columns:1fr}.adminSheet{grid-column:1;width:100%;border-left:0}.filterGrid{grid-template-columns:1fr 1fr}}
@media(max-width:560px){.side,.main{padding:12px!important}.top{padding:12px!important}.topActions{display:flex;width:100%}.topActions>button{flex:1}.quickMenu{flex:0 0 auto}.messages{gap:10px}.filterGrid{grid-template-columns:1fr}.detailHeader{display:block}.detailHeader .toolbar{margin-top:10px;justify-content:flex-start}.detailHeader .toolbar button{flex:1}.adminSheet{padding:12px}.adminDrawerHeader{top:-12px;margin:-12px -12px 10px;padding:12px}.adminSheet .adminNav{top:49px;overflow:auto;flex-wrap:nowrap}.adminSheet .adminNav button{flex:0 0 auto}.modal{align-items:flex-end}.modalCard{border-radius:10px 10px 0 0}}
</style>
<style id="skyline-ui-v2">
/* SkyMail visual system: a bright working surface with richer depth and strict mail readability. */
:root[data-visual="skyline"]{
  color-scheme:light;
  --bg:#eaf7ff;--panel:rgba(255,255,255,.88);--panel2:#f4fbff;--panel3:#e5f5ff;
  --text:#17354d;--muted:#6c879b;--border:rgba(87,166,213,.25);
  --accent:#168fe0;--accent2:#10aa9f;--accentSoft:#d9f1ff;
  --danger:#e4586e;--dangerBg:#fff2f4;--dangerBorder:#f5bbc5;
  --shadow:0 18px 46px rgba(38,123,177,.13),0 2px 8px rgba(51,133,184,.07);
  --shadowSoft:0 10px 28px rgba(48,135,190,.1);
  --glow:0 0 0 4px rgba(42,165,237,.13),0 12px 30px rgba(32,143,211,.18);
}
:root[data-theme="dark"][data-visual="skyline"]{
  color-scheme:dark;--bg:#17191d;--panel:rgba(30,34,40,.94);--panel2:#232a33;--panel3:#2b3541;
  --text:#e8f7ff;--muted:#9eb9cb;--border:rgba(126,199,238,.2);--accent:#55bcff;--accent2:#43d7c9;
  --accentSoft:#173f59;--dangerBg:#3a2029;--dangerBorder:#7f4050;
  --shadow:0 18px 48px rgba(0,0,0,.25);--shadowSoft:0 10px 28px rgba(0,0,0,.2);
}
html[data-visual="skyline"],html[data-visual="skyline"] body{background:var(--bg)}
html[data-visual="skyline"] body{
  position:relative;color:var(--text);
  background:
    radial-gradient(circle at 10% 10%,rgba(255,255,255,.96) 0 5%,transparent 24%),
    radial-gradient(circle at 92% 8%,rgba(91,199,255,.25),transparent 28%),
    linear-gradient(145deg,#effaff 0%,#e2f5ff 46%,#f7fcff 100%)!important;
}
html[data-theme="dark"][data-visual="skyline"] body{background:linear-gradient(145deg,#17191d,#1b1e23 55%,#17191d)!important}
html[data-visual="skyline"] body:before,
html[data-visual="skyline"] body:after{
  display:block!important;content:"";position:fixed;pointer-events:none;z-index:0;border-radius:50%;filter:blur(1px);
  background:radial-gradient(circle at 36% 34%,rgba(255,255,255,.95),rgba(153,220,255,.22) 48%,transparent 70%);
  animation:skyDrift 15s ease-in-out infinite alternate;
}
html[data-visual="skyline"] body:before{width:430px;height:430px;right:-130px;top:-135px}
html[data-visual="skyline"] body:after{width:300px;height:300px;left:-95px;bottom:-115px;animation-delay:-7s;animation-duration:18s}
@keyframes skyDrift{to{transform:translate3d(-22px,28px,0) scale(1.07)}}
@keyframes skyRise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes skyPulse{50%{box-shadow:0 0 0 7px rgba(32,184,168,0)}}
@keyframes skyShimmer{to{transform:translateX(140%) rotate(15deg)}}

html[data-visual="skyline"] .app{
  position:relative;z-index:1;grid-template-columns:340px minmax(0,1fr)!important;
  background:transparent!important;isolation:isolate;
}
html[data-visual="skyline"] .side{
  position:relative;padding:22px 17px!important;gap:14px;
  background:linear-gradient(180deg,rgba(255,255,255,.92),rgba(239,250,255,.85))!important;
  border-right:1px solid rgba(91,169,215,.25)!important;
  box-shadow:14px 0 48px rgba(36,125,181,.09)!important;
  scrollbar-color:#a8d7f2 transparent;
}
html[data-theme="dark"][data-visual="skyline"] .side{background:linear-gradient(180deg,rgba(18,43,60,.96),rgba(13,34,49,.94))!important}
html[data-visual="skyline"] .side:before{
  content:"";position:absolute;left:0;right:0;top:0;height:5px;display:block!important;
  background:linear-gradient(90deg,#12b8ae,#44b9ff,#7f8dff);box-shadow:0 4px 18px rgba(40,163,230,.3)
}
html[data-visual="skyline"] .main{padding:22px!important;gap:15px;background:transparent!important}
html[data-visual="skyline"] .sidebarBrand{
  display:flex;align-items:center;gap:12px;padding:6px 5px 12px!important;border:0!important;
}
html[data-visual="skyline"] .skyMark{
  flex:0 0 48px;width:48px;height:48px;display:grid;place-items:center;border-radius:16px;color:#fff;font-size:23px;
  background:linear-gradient(145deg,#5dc8ff,#168fe0 57%,#6f7ff7);
  box-shadow:0 10px 25px rgba(28,148,219,.3),inset 0 1px rgba(255,255,255,.55);
  transform:rotate(-4deg);transition:transform .35s ease,box-shadow .35s ease;
}
html[data-visual="skyline"] .skyMark span{filter:drop-shadow(0 2px 4px rgba(28,83,149,.25));animation:skyPulse 2.5s ease-in-out infinite}
html[data-visual="skyline"] .sidebarBrand:hover .skyMark{transform:rotate(4deg) scale(1.05);box-shadow:0 14px 30px rgba(28,148,219,.38)}
html[data-visual="skyline"] .brandCopy{min-width:0}
html[data-visual="skyline"] .brandEyebrow,
html[data-visual="skyline"] .topEyebrow{
  color:#168fd8;font-size:10px;font-weight:900;letter-spacing:.18em;text-transform:uppercase;line-height:1.2
}
html[data-visual="skyline"] .sidebarBrand .brand{margin:2px 0 1px;font-size:20px!important;font-weight:900;letter-spacing:-.025em!important}
html[data-visual="skyline"] .sidebarBrand .muted{font-size:12px}

html[data-visual="skyline"] .box,
html[data-visual="skyline"] .list,
html[data-visual="skyline"] .detail,
html[data-visual="skyline"] .top{
  border:1px solid rgba(100,178,222,.24)!important;border-radius:18px!important;
  background:var(--panel)!important;box-shadow:var(--shadow)!important;
  backdrop-filter:blur(18px) saturate(125%);-webkit-backdrop-filter:blur(18px) saturate(125%);
}
html[data-visual="skyline"] .box{padding:15px}
html[data-visual="skyline"] .box,
html[data-visual="skyline"] .top,
html[data-visual="skyline"] .messages{animation:skyRise .5s both}
html[data-visual="skyline"] .side>.box:nth-of-type(2){animation-delay:.04s}
html[data-visual="skyline"] .side>.box:nth-of-type(3){animation-delay:.08s}
html[data-visual="skyline"] .top{
  position:relative;overflow:visible;padding:17px 19px!important;
  background:linear-gradient(115deg,rgba(255,255,255,.96),rgba(232,247,255,.89))!important;
}
html[data-theme="dark"][data-visual="skyline"] .top{background:linear-gradient(115deg,rgba(21,50,69,.97),rgba(19,59,82,.92))!important}
html[data-visual="skyline"] .top:after{
  content:"";position:absolute;right:14%;top:-1px;width:120px;height:2px;border-radius:99px;
  background:linear-gradient(90deg,transparent,#44baff,transparent);filter:drop-shadow(0 3px 7px #44baff)
}
html[data-visual="skyline"] .topIdentity{min-width:0}
html[data-visual="skyline"] .topIdentity .brand{font-size:21px!important;font-weight:900;letter-spacing:-.025em}
html[data-visual="skyline"] .topIdentity .muted{margin-top:3px}
html[data-visual="skyline"] .sectionTitle{
  display:flex;align-items:center;gap:8px;margin-bottom:11px;color:var(--text)!important;
  font-size:12px;font-weight:850;letter-spacing:.08em!important
}
html[data-visual="skyline"] .sectionTitle:before{
  display:block!important;content:"";width:7px;height:7px;border-radius:50%;
  background:linear-gradient(135deg,#37b7ff,#13b9a9);box-shadow:0 0 0 4px rgba(49,172,232,.12)
}

html[data-visual="skyline"] button,
html[data-visual="skyline"] a.secondary{
  min-height:38px;border:0;border-radius:11px;padding:0 14px;font-weight:750;letter-spacing:.01em;
  color:#fff;background:linear-gradient(135deg,#29a8ee,#147fc9);
  box-shadow:0 7px 17px rgba(28,139,205,.19),inset 0 1px rgba(255,255,255,.28);
  transition:transform .18s ease,box-shadow .18s ease,filter .18s ease,border-color .18s ease;
}
html[data-visual="skyline"] button:hover,
html[data-visual="skyline"] a.secondary:hover{transform:translateY(-2px);filter:saturate(1.08);box-shadow:0 11px 22px rgba(28,139,205,.25)}
html[data-visual="skyline"] button:active,
html[data-visual="skyline"] a.secondary:active{transform:translateY(0) scale(.98)}
html[data-visual="skyline"] button:focus-visible,
html[data-visual="skyline"] a:focus-visible,
html[data-visual="skyline"] input:focus-visible,
html[data-visual="skyline"] select:focus-visible,
html[data-visual="skyline"] summary:focus-visible{outline:3px solid rgba(33,159,229,.25);outline-offset:2px}
html[data-visual="skyline"] button.secondary,
html[data-visual="skyline"] a.secondary,
html[data-visual="skyline"] .quickMenu>summary{
  color:#26769f!important;background:rgba(255,255,255,.86)!important;border:1px solid #cde8f7!important;
  box-shadow:0 5px 14px rgba(48,135,181,.08)!important;
}
html[data-theme="dark"][data-visual="skyline"] button.secondary,
html[data-theme="dark"][data-visual="skyline"] a.secondary,
html[data-theme="dark"][data-visual="skyline"] .quickMenu>summary{color:#bce9ff!important;background:#183d55!important;border-color:#2b607e!important}
html[data-visual="skyline"] button.secondary:hover,
html[data-visual="skyline"] a.secondary:hover,
html[data-visual="skyline"] .quickMenu>summary:hover{border-color:#82c9ee!important;background:#f7fdff!important}
html[data-visual="skyline"] button.danger{background:linear-gradient(135deg,#ef7183,#d94a64);box-shadow:0 7px 17px rgba(217,74,100,.17)}
html[data-visual="skyline"] button.softDanger{color:#d84e66!important;background:#fff4f6!important;border:1px solid #f8ccd3!important;box-shadow:none!important}
html[data-visual="skyline"] button:disabled{opacity:.48;transform:none;filter:saturate(.5);box-shadow:none}

html[data-visual="skyline"] input,
html[data-visual="skyline"] select,
html[data-visual="skyline"] textarea{
  min-height:40px;border:1px solid #cde6f5;border-radius:11px;color:var(--text);
  background:rgba(255,255,255,.88);box-shadow:inset 0 1px 2px rgba(53,123,164,.04);
  transition:border-color .18s ease,box-shadow .18s ease,background .18s ease
}
html[data-theme="dark"][data-visual="skyline"] input,
html[data-theme="dark"][data-visual="skyline"] select,
html[data-theme="dark"][data-visual="skyline"] textarea{background:#122f43;border-color:#2a5874}
html[data-visual="skyline"] input:hover,
html[data-visual="skyline"] select:hover{border-color:#91cdec}
html[data-visual="skyline"] input:focus,
html[data-visual="skyline"] select:focus,
html[data-visual="skyline"] textarea:focus{border-color:#3facf0;background:var(--panel);box-shadow:var(--glow)}
html[data-visual="skyline"] input::placeholder{color:#9aafbd}

html[data-visual="skyline"] .livePill{
  min-height:32px;padding:0 11px!important;border:1px solid rgba(28,173,157,.22)!important;border-radius:99px!important;
  color:#099b8f!important;background:rgba(226,252,248,.78)!important;font-weight:800
}
html[data-visual="skyline"] .livePill:before{animation:skyPulse 1.8s infinite;background:#18b7a9;box-shadow:0 0 0 4px rgba(24,183,169,.16)}
html[data-visual="skyline"] .quickMenuPanel{
  padding:9px;gap:7px;border-radius:14px;background:rgba(255,255,255,.96);border:1px solid #cae6f5;
  box-shadow:0 20px 50px rgba(27,101,147,.2);backdrop-filter:blur(18px)
}

html[data-visual="skyline"] .alias{
  position:relative;padding:10px 11px!important;border:1px solid transparent;border-radius:13px!important;
  background:rgba(246,252,255,.8)!important;transition:transform .18s ease,background .18s ease,border-color .18s ease,box-shadow .18s ease
}
html[data-visual="skyline"] .alias:hover{transform:translateX(3px);border-color:#bfe4f7;background:#fff!important;box-shadow:var(--shadowSoft)}
html[data-visual="skyline"] .alias.active{
  background:linear-gradient(115deg,#e2f5ff,#f3fbff)!important;border-color:#8fd0f2!important;
  box-shadow:inset 3px 0 #1a99df,0 8px 20px rgba(32,137,196,.1)
}
html[data-theme="dark"][data-visual="skyline"] .alias,
html[data-theme="dark"][data-visual="skyline"] .alias.active{background:#16384f!important}
html[data-visual="skyline"] .aliasOpen{background:transparent!important;color:inherit!important;border:0!important;box-shadow:none!important;transform:none!important}
html[data-visual="skyline"] .aliasActions button{min-height:29px;border-radius:8px;padding:0 8px;font-size:11px;box-shadow:none!important}
html[data-visual="skyline"] .fold>summary,
html[data-visual="skyline"] .domainStatsFold>summary{padding:2px 0;font-weight:750}
html[data-visual="skyline"] .mailTools>summary{padding:12px 15px}

html[data-visual="skyline"] .messages{grid-template-columns:minmax(315px,380px) minmax(0,1fr);gap:15px}
html[data-visual="skyline"] .list{padding:8px;scrollbar-color:#acd9ef transparent}
html[data-visual="skyline"] .mail{
  position:relative;margin:0 0 8px;padding:14px 13px;gap:10px;border:1px solid transparent;border-radius:14px;
  background:rgba(255,255,255,.58)!important;transition:transform .2s ease,box-shadow .2s ease,background .2s ease,border-color .2s ease
}
html[data-visual="skyline"] .mail:last-child{margin-bottom:0}
html[data-visual="skyline"] .mail:hover{transform:translateY(-2px);background:#fff!important;border-color:#c4e4f5;box-shadow:0 10px 25px rgba(41,128,181,.12)}
html[data-visual="skyline"] .mail.active{
  border:1px solid #77c6ee!important;border-left:1px solid #77c6ee!important;
  background:linear-gradient(135deg,#e5f6ff,#f8fdff)!important;box-shadow:0 10px 26px rgba(30,142,205,.15)
}
html[data-visual="skyline"] .mail.active:before{
  content:"";position:absolute;left:-1px;top:14px;bottom:14px;width:4px;border-radius:0 4px 4px 0;
  background:linear-gradient(#1aa8e9,#14b6a8);box-shadow:0 0 12px rgba(24,166,219,.35)
}
html[data-visual="skyline"] .mail.unread .subject{font-weight:900;color:#0b75b4}
html[data-visual="skyline"] .mail .subject{line-height:1.45;color:var(--text)}
html[data-visual="skyline"] .mail .preview{color:#7891a3}
html[data-visual="skyline"] .flag{border-radius:99px;padding:2px 7px;color:#477c99;background:#edf8fe!important;border:1px solid #d4ecf9!important}
html[data-visual="skyline"] .flag.hot{color:#e05970;background:#fff0f3!important;border-color:#ffd2d9!important}
html[data-visual="skyline"] .code{
  border:1px solid #9ee7df!important;border-radius:8px!important;color:#078f84!important;
  background:#e8fcf9!important;box-shadow:0 3px 10px rgba(12,167,153,.1)!important
}

html[data-visual="skyline"] .detail{padding:0!important;background:rgba(246,252,255,.87)!important;scrollbar-color:#acd9ef transparent}
html[data-visual="skyline"] .detailHeader{
  position:sticky;top:0;z-index:8;margin:0;padding:21px 23px 17px;
  background:linear-gradient(120deg,rgba(255,255,255,.98),rgba(227,246,255,.96))!important;
  border-bottom:1px solid #cae8f7;box-shadow:0 8px 26px rgba(55,134,179,.08);backdrop-filter:blur(20px)
}
html[data-theme="dark"][data-visual="skyline"] .detailHeader{background:linear-gradient(120deg,#193b52,#16405a)!important}
html[data-visual="skyline"] .detailHeader:before{
  content:"MAIL";position:absolute;right:22px;bottom:8px;font-size:48px;font-weight:950;letter-spacing:.08em;
  color:rgba(62,169,224,.055);pointer-events:none
}
html[data-visual="skyline"] .detail h2{margin:0 0 7px;font-size:22px;letter-spacing:-.025em;color:var(--text)}
html[data-visual="skyline"] .detail>.actions,
html[data-visual="skyline"] .detail>.attachList{margin:14px 22px 0}
html[data-visual="skyline"] .detail>.tabs{
  position:sticky;top:106px;z-index:7;margin:0;padding:14px 22px 10px;
  background:linear-gradient(rgba(246,252,255,.98),rgba(246,252,255,.9),transparent);
  backdrop-filter:blur(10px)
}
html[data-visual="skyline"] .tabBtn{min-height:34px!important;border-radius:99px!important;padding:0 13px!important}
html[data-visual="skyline"] .tabBtn.active{
  color:#fff!important;border-color:transparent!important;background:linear-gradient(135deg,#2baced,#1386cf)!important;
  box-shadow:0 7px 16px rgba(29,143,207,.22)!important
}
html[data-visual="skyline"] #mailBodyBox{
  position:relative;margin:0 22px 22px;padding:12px;min-height:360px;border:1px solid #cbe6f5;border-radius:20px;
  color:#1b3449;background:#fff!important;box-shadow:0 18px 42px rgba(45,125,172,.12),inset 0 1px rgba(255,255,255,.9);
}
html[data-visual="skyline"] #mailBodyBox:before{
  content:"邮件正文";position:absolute;right:22px;top:17px;z-index:1;color:#b3d4e7;
  font-size:10px;font-weight:850;letter-spacing:.15em;pointer-events:none
}
html[data-visual="skyline"] .frame{
  display:block;width:100%;min-height:520px;border:0!important;border-radius:13px;background:#fff!important;
  box-shadow:inset 0 0 0 1px #edf5fa
}
html[data-visual="skyline"] .plainView{
  min-height:470px;padding:24px!important;border:0!important;border-radius:13px;color:#1b3449!important;
  background:#fff!important;font-size:14px;line-height:1.72;white-space:pre-wrap;overflow-wrap:anywhere
}
html[data-visual="skyline"] .empty{border-radius:14px;color:#7d97a9;background:linear-gradient(135deg,rgba(244,251,255,.8),rgba(255,255,255,.7))}

html[data-visual="skyline"] .toast{
  border:1px solid rgba(118,195,232,.35);border-radius:15px;background:rgba(255,255,255,.96);
  box-shadow:0 20px 48px rgba(31,105,149,.22);backdrop-filter:blur(18px);animation:skyRise .28s ease-out
}
html[data-visual="skyline"] .modal{backdrop-filter:blur(7px)}
html[data-visual="skyline"] .modalCard{border-radius:20px;border:1px solid #c7e5f5;box-shadow:0 30px 70px rgba(28,94,135,.25)}
html[data-visual="skyline"] .adminDrawerBackdrop{background:rgba(18,69,99,.42)!important;backdrop-filter:blur(5px)}
html[data-visual="skyline"] .adminSheet{
  background:linear-gradient(160deg,#effaff,#f9fdff);border-left:1px solid rgba(119,195,235,.4);
  box-shadow:-24px 0 65px rgba(19,83,122,.22);animation:drawerIn .35s cubic-bezier(.2,.8,.2,1)
}
@keyframes drawerIn{from{transform:translateX(45px);opacity:.6}to{transform:none;opacity:1}}
html[data-theme="dark"][data-visual="skyline"] .adminSheet{background:#102b3d}
html[data-visual="skyline"] .adminDrawerHeader{background:rgba(245,252,255,.9);border-bottom-color:#cce8f6}
html[data-theme="dark"][data-visual="skyline"] .adminDrawerHeader{background:rgba(16,43,61,.92)}

/* Global type and control rhythm: keep every management surface comfortably readable. */
html[data-visual="skyline"] body{font-size:15px;line-height:1.55;-webkit-text-size-adjust:100%;text-rendering:optimizeLegibility}
html[data-visual="skyline"] .app{grid-template-columns:360px minmax(0,1fr)!important}
html[data-visual="skyline"] .muted,
html[data-visual="skyline"] .meta,
html[data-visual="skyline"] .preview,
html[data-visual="skyline"] .empty,
html[data-visual="skyline"] .err,
html[data-visual="skyline"] .domainAddHelp,
html[data-visual="skyline"] .cloudflareGuideHelp,
html[data-visual="skyline"] .webhookHint{font-size:13.5px!important;line-height:1.6}
html[data-visual="skyline"] .sidebarBrand .muted{font-size:13px!important}
html[data-visual="skyline"] .sectionTitle,
html[data-visual="skyline"] .domainAddTitle,
html[data-visual="skyline"] .accessTitle{font-size:14.5px!important;line-height:1.4}
html[data-visual="skyline"] .brandEyebrow,
html[data-visual="skyline"] .topEyebrow{font-size:11px}

html[data-visual="skyline"] button,
html[data-visual="skyline"] a.secondary,
html[data-visual="skyline"] .quickMenu>summary{
  min-height:42px;font-size:14px;line-height:1.25
}
html[data-visual="skyline"] input,
html[data-visual="skyline"] select,
html[data-visual="skyline"] textarea{
  min-height:44px;height:auto;font-size:14.5px;line-height:1.4;padding-top:9px;padding-bottom:9px
}
html[data-visual="skyline"] select{padding-top:0;padding-bottom:0}
html[data-visual="skyline"] textarea.batchArea{min-height:110px!important;padding:12px;line-height:1.6;resize:vertical}
html[data-visual="skyline"] input[type="checkbox"],
html[data-visual="skyline"] input[type="radio"],
html[data-visual="skyline"] .mailCheck{
  width:18px!important;height:18px!important;min-height:18px!important;padding:0!important;flex:0 0 18px
}
html[data-visual="skyline"] .livePill{min-height:36px;font-size:13px}

html[data-visual="skyline"] .fold,
html[data-visual="skyline"] .domainStatsFold{overflow:hidden}
html[data-visual="skyline"] .fold>summary,
html[data-visual="skyline"] .domainStatsFold>summary,
html[data-visual="skyline"] .deleteClearBox>summary,
html[data-visual="skyline"] .cloudflareGuideSummary{
  display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:46px;
  padding:11px 13px!important;font-size:14.5px!important;line-height:1.4;font-weight:800;
  color:var(--text)!important;background:linear-gradient(110deg,rgba(244,251,255,.9),rgba(255,255,255,.75))!important;
  border-radius:12px;transition:background .18s ease,color .18s ease
}
html[data-theme="dark"][data-visual="skyline"] .fold>summary,
html[data-theme="dark"][data-visual="skyline"] .domainStatsFold>summary,
html[data-theme="dark"][data-visual="skyline"] .deleteClearBox>summary,
html[data-theme="dark"][data-visual="skyline"] .cloudflareGuideSummary{background:linear-gradient(110deg,#183d55,#153448)!important}
html[data-visual="skyline"] .fold>summary:hover,
html[data-visual="skyline"] .domainStatsFold>summary:hover{background:#edf9ff!important;color:#087bc8!important}
html[data-visual="skyline"] .fold>summary:after,
html[data-visual="skyline"] .domainStatsFold>summary:after{
  float:none;margin-left:auto;flex:0 0 auto;padding:3px 8px;border-radius:99px;
  color:#4f89a8;font-size:12.5px;font-weight:750!important;background:rgba(212,239,253,.72)
}
html[data-visual="skyline"] .fold[open]>summary,
html[data-visual="skyline"] .domainStatsFold[open]>summary{border-bottom:1px solid #d4ebf7;border-radius:12px 12px 7px 7px}
html[data-visual="skyline"] .foldBody,
html[data-visual="skyline"] .domainStatsBody{padding:14px!important;gap:10px}
html[data-visual="skyline"] .mailTools>summary{padding:12px 16px!important}

html[data-visual="skyline"] .alias .email{font-size:14.5px!important;line-height:1.45}
html[data-visual="skyline"] .alias .meta{font-size:13px!important}
html[data-visual="skyline"] .aliasActions button,
html[data-visual="skyline"] .accessToolbar button,
html[data-visual="skyline"] .cloudflareGuideHeaderActions button,
html[data-visual="skyline"] .adminTable button,
html[data-visual="skyline"] .adminTable a.secondary{
  min-height:34px;font-size:12.5px;padding:0 9px
}
html[data-visual="skyline"] .mail .subject{font-size:15px!important;line-height:1.5}
html[data-visual="skyline"] .mail .preview{font-size:13px!important;line-height:1.5;margin-top:5px}
html[data-visual="skyline"] .flag{font-size:12px;line-height:1.35;padding:3px 8px}
html[data-visual="skyline"] .codeQuickBtn{font-size:13px;min-height:30px!important;padding:2px 9px}
html[data-visual="skyline"] .checkLine{font-size:13.5px;line-height:1.4}
html[data-visual="skyline"] .pill,
html[data-visual="skyline"] .accessBadge{font-size:12.5px;line-height:1.35}
html[data-visual="skyline"] .accessStep{font-size:12.5px;line-height:1.4}
html[data-visual="skyline"] .tabBtn{min-height:38px!important;font-size:13.5px}
html[data-visual="skyline"] .detailHeader .muted{font-size:13.5px!important;line-height:1.6}
html[data-visual="skyline"] .detail>.actions a{min-height:40px;display:inline-flex;align-items:center;font-size:14px}

html[data-visual="skyline"] .adminNav button{min-height:38px;font-size:13.5px}
html[data-visual="skyline"] .adminTable{font-size:13px;line-height:1.5}
html[data-visual="skyline"] .adminTable th,
html[data-visual="skyline"] .adminTable td{padding:10px}
html[data-visual="skyline"] .settingsGroupTitle{font-size:13.5px}
html[data-visual="skyline"] .copyTokenLine,
html[data-visual="skyline"] .logBox,
html[data-visual="skyline"] .dns,
html[data-visual="skyline"] .previewBox,
html[data-visual="skyline"] .rulePreview b,
html[data-visual="skyline"] .rulePreview div{font-size:12.5px;line-height:1.6}
html[data-visual="skyline"] #overviewStats .stat{min-height:44px;padding:9px 11px}
html[data-visual="skyline"] #overviewStats .stat b{font-size:17px}
html[data-visual="skyline"] #overviewStats .stat .muted{font-size:13px!important}
html[data-visual="skyline"] .toast{font-size:14px;line-height:1.55}
html[data-visual="skyline"] .modalText{font-size:14.5px;line-height:1.65}

html[data-visual="skyline"] body:not(.isAuthed) .app{
  grid-template-columns:minmax(320px,440px)!important;place-content:center;padding:8vh 18px;
}
html[data-visual="skyline"] body:not(.isAuthed) .side{
  position:relative;max-width:440px;padding:28px!important;border:1px solid rgba(114,191,232,.42)!important;border-radius:26px;
  box-shadow:0 32px 80px rgba(34,117,168,.2)!important;overflow:hidden
}
html[data-visual="skyline"] body:not(.isAuthed) .side:after{
  content:"";position:absolute;right:-42px;top:-42px;width:130px;height:130px;border-radius:50%;
  background:radial-gradient(circle,rgba(75,184,241,.2),transparent 68%);pointer-events:none
}
html[data-visual="skyline"] body:not(.isAuthed) #loginBox{padding:18px;border-radius:17px!important}

@media(max-width:1400px){
  html[data-visual="skyline"] .detailHeader{display:block}
  html[data-visual="skyline"] .detailHeader .toolbar{margin-top:13px;justify-content:flex-start}
}
@media(max-width:1180px){
  html[data-visual="skyline"] .app{grid-template-columns:320px minmax(0,1fr)!important}
  html[data-visual="skyline"] .messages{grid-template-columns:minmax(285px,340px) minmax(0,1fr)}
}
@media(max-width:980px){
  html[data-visual="skyline"] .app{display:block!important;height:auto;min-height:100vh;overflow:visible;grid-template-columns:1fr!important}
  html[data-visual="skyline"] .side{max-height:44vh;overflow:auto;padding:17px!important;border-bottom:1px solid #bfe3f5!important}
  html[data-visual="skyline"] .main{display:grid!important;min-height:100vh;overflow:visible!important;padding:15px!important}
  html[data-visual="skyline"] .sidebarBrand{position:sticky;top:0;z-index:6;background:rgba(247,252,255,.92);backdrop-filter:blur(12px)}
  html[data-visual="skyline"] .messages{grid-template-columns:1fr}
  html[data-visual="skyline"] .list{max-height:45vh}
  html[data-visual="skyline"] .detail{min-height:60vh}
  html[data-visual="skyline"] .detail>.tabs{top:0}
}
@media(max-width:560px){
  html[data-visual="skyline"] .side,html[data-visual="skyline"] .main{padding:11px!important}
  html[data-visual="skyline"] .skyMark{width:42px;height:42px;flex-basis:42px;border-radius:14px}
  html[data-visual="skyline"] .top{padding:14px!important}
  html[data-visual="skyline"] .topIdentity{width:100%}
  html[data-visual="skyline"] .topActions{display:grid;grid-template-columns:1fr 1fr auto}
  html[data-visual="skyline"] button,html[data-visual="skyline"] a.secondary,html[data-visual="skyline"] .quickMenu>summary{font-size:14px}
  html[data-visual="skyline"] .fold>summary,html[data-visual="skyline"] .domainStatsFold>summary{min-height:48px;font-size:15px!important}
  html[data-visual="skyline"] .detailHeader{padding:17px 15px 14px}
  html[data-visual="skyline"] .detailHeader .toolbar{display:grid;grid-template-columns:1fr 1fr}
  html[data-visual="skyline"] .detail>.actions,html[data-visual="skyline"] .detail>.attachList{margin:11px 13px 0}
  html[data-visual="skyline"] .detail>.tabs{padding:11px 13px 8px;overflow:auto;flex-wrap:nowrap}
  html[data-visual="skyline"] .tabBtn{flex:0 0 auto!important}
  html[data-visual="skyline"] #mailBodyBox{margin:0 12px 14px;padding:7px;border-radius:15px}
  html[data-visual="skyline"] .frame{min-height:460px}
  html[data-visual="skyline"] .plainView{min-height:420px;padding:18px!important}
}
@media(prefers-reduced-motion:reduce){
  html[data-visual="skyline"] *,html[data-visual="skyline"] *:before,html[data-visual="skyline"] *:after{
    animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important
  }
}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="sidebarBrand">
      <div class="skyMark" aria-hidden="true"><span>✦</span></div>
      <div class="brandCopy">
        <div class="brandEyebrow">Ferret SkyMail</div>
        <div class="brand">__BRAND_TITLE__</div>
        <div class="muted">__BRAND_DESC__</div>
      </div>
    </div>
    <div class="box" id="loginBox">
      <div class="sectionTitle">登录</div>
      <form class="row" id="tokenForm"><input id="token" type="password" placeholder="输入 Token" aria-label="访问 Token" autocomplete="current-password"><button id="saveToken" type="submit">进入</button></form>
      <div class="err" id="loginErr"></div>
    </div>
    __ADMIN_BLOCK__
    __ADMIN_OPS_BLOCK__
    <div class="box">
      <div class="sectionTitle">新建别名</div>
      <div class="row"><input id="aliasInput" placeholder="例如 user"><button id="addAlias">添加</button></div>
      <div class="muted" style="margin-top:7px" id="aliasPreview">输入前缀即可创建</div>
    </div>
    <details class="box fold" id="batchBox">
      <summary>批量生成</summary>
      <div class="foldBody">
      <div class="generatorGrid">
        <select id="ruleSelect"></select>
        <input id="batchBase" placeholder="前缀" value="">
        <input id="batchCount" type="number" min="1" max="10000" value="20">
      </div>
      <div class="compactGrid" style="margin-top:8px">
        <input id="batchStart" type="number" min="0" value="1">
        <input id="customTemplate" placeholder="自定义：{base}-{n:3}">
      </div>
      <div class="previewBox" id="batchPreview" style="margin-top:8px"></div>
      <div class="rulePreviewGrid" id="rulePreviewGrid"></div>
      <div class="toolbar" style="margin-top:8px"><button id="addBatch">一键添加</button></div>
      <div class="err" id="batchErr"></div>
      </div>
    </details>
    <div class="box" id="aliasListBox">
      <div class="aliasListHead"><div class="sectionTitle">邮箱别名</div><div class="muted" id="aliasListSummary">0 个</div></div>
      <details class="domainStatsFold aliasToolsFold" id="aliasToolsFold">
        <summary>搜索与批量操作</summary>
        <div class="domainStatsBody">
          <div class="row"><input id="aliasSearch" placeholder="搜索别名"><select id="aliasPageSize"><option>50</option><option>100</option><option>200</option></select></div>
          <div class="pager" style="margin-top:8px"><button class="secondary" id="aliasPrev">上一页</button><div class="muted" id="aliasPageInfo">0 个别名</div><button class="secondary" id="aliasNext">下一页</button></div>
          <div class="toolbar" style="margin-top:8px"><button class="secondary" id="exportAliasLinks">导出接码链接</button></div>
          <details class="deleteClearBox">
            <summary>删除清空操作区</summary>
            <div class="deleteClearBody">
              <div class="muted">这里是不可逆或影响较大的操作，日常管理不需要打开。</div>
              <div class="toolbar"><button class="softDanger" id="clearAliases">清空当前域名所有别名</button></div>
            </div>
          </details>
        </div>
      </details>
      <div class="aliases" id="aliases"></div>
    </div>
    <div class="toolbar sidebarFooter"><button class="secondary" id="refreshAll">刷新全部</button><button class="secondary" id="clearToken">退出</button><a class="secondary" href="/api-docs.md" download>API</a><a class="secondary" href="/usage-guide.md" download>帮助</a></div>
  </aside>
  <main class="main">
    <div class="top">
      <div class="topIdentity">
        <div class="topEyebrow">Live inbox</div>
        <div class="brand" id="currentTitle">请选择别名</div>
        <div class="muted" id="currentMeta">选择别名查看邮件</div>
      </div>
      <div class="toolbar topActions"><span class="pill livePill" id="liveStatus">连接中</span><button id="copyAddress">复制邮箱</button><button id="refreshMessages" class="secondary">刷新</button><details class="quickMenu"><summary class="secondary">更多</summary><div class="quickMenuPanel"><button id="notifyToggle" class="secondary">邮件通知</button><button class="secondary" id="themeToggle">深色模式</button><label class="muted" for="visualTheme">浅色主题</label><select id="visualTheme" aria-label="选择全局浅色主题"><option value="skyline">天光</option><option value="moyu">墨玉</option><option value="minimal">素纸</option></select><a class="secondary" href="/api-docs.md" download>API 文档</a><a class="secondary" href="/usage-guide.md" download>使用帮助</a></div></details></div>
    </div>
    <details class="box fold mailTools" id="mailFilterBox">
      <summary>筛选 / 批量操作</summary>
      <div class="foldBody">
      <div class="filterGrid">
        <input id="mailSearch" placeholder="搜索发件人 / 主题 / 收件地址 / 正文">
        <input id="mailCodeSearch" placeholder="搜索验证码">
        <input id="mailDateFrom" type="date" title="开始日期">
        <input id="mailDateTo" type="date" title="结束日期">
        <select id="mailScope"><option value="alias">当前别名</option><option value="domain">当前域名</option></select>
        <select id="mailPageSize"><option>50</option><option>100</option></select>
      </div>
      <div class="toolbar">
        <label class="checkLine"><input type="checkbox" id="filterCode">验证码邮件</label>
        <label class="checkLine"><input type="checkbox" id="filterLink">含链接</label>
        <label class="checkLine"><input type="checkbox" id="filterUnread">未读</label>
        <label class="checkLine"><input type="checkbox" id="filterToday">今天</label>
        <label class="checkLine"><input type="checkbox" id="filterStarred">星标</label>
        <label class="checkLine"><input type="checkbox" id="filterPinned">置顶</label>
      </div>
      <div class="toolbar">
        <button class="secondary" id="selectAllMail">全选本页</button>
        <button class="secondary" id="bulkRead">标记已读</button>
        <button class="secondary" id="bulkUnread">标记未读</button>
        <button class="secondary" id="bulkCopyCodes">复制验证码</button>
      </div>
      <details class="deleteClearBox">
        <summary>删除清空操作区</summary>
        <div class="deleteClearBody">
          <div class="muted">删除和清空操作不可恢复；批量清空会要求输入确认。</div>
          <div class="toolbar"><button class="softDanger" id="bulkDelete">批量删除</button><button class="softDanger" id="clearAliasMail">清空当前别名邮件</button><button class="danger" id="clearDomainMail">清空当前域名邮件</button></div>
        </div>
      </details>
      <div class="mailPager"><button class="secondary" id="mailPrev">上一页</button><div class="muted" id="mailPageInfo">0 封邮件</div><button class="secondary" id="mailNext">下一页</button></div>
      </div>
    </details>
    <section class="messages">
      <div class="list" id="mailList"><div class="empty">选择左侧别名开始收件。</div></div>
      <div class="detail" id="mailDetail"><div class="empty">选择一封邮件查看内容。</div></div>
    </section>
  </main>
</div>
<div class="toastStack" id="toastStack" aria-live="polite" aria-atomic="true"></div>
<div class="modal hidden" id="dangerModal" role="dialog" aria-modal="true">
  <div class="modalCard">
    <div class="modalTitle" id="dangerTitle"></div>
    <div class="modalText" id="dangerText"></div>
    <input class="modalInput hidden" id="dangerInput">
    <div class="toolbar"><button class="secondary" id="dangerCancel">取消</button><button class="danger" id="dangerConfirm">确认</button></div>
  </div>
</div>
<script>
const DOMAIN="__DOMAIN__",BASE_DOMAIN="__BASE_DOMAIN__",DEFAULT_ROOT_DOMAIN="__DEFAULT_ROOT_DOMAIN__",PUBLIC_IP="__PUBLIC_IP__",DEFAULT_ALIAS="__DEFAULT_ALIAS__",ROOT_PAGE=DOMAIN===BASE_DOMAIN;
const TOKEN_KEY="ferret_mail_token_"+DOMAIN,CURRENT_KEY="ferret_mail_current_"+DOMAIN;
const $=(s,root=document)=>root.querySelector(s),$$=(s,root=document)=>Array.from(root.querySelectorAll(s));
const byId=id=>document.getElementById(id);
function storeGet(k,d=""){try{return localStorage.getItem(k)||d}catch(e){return d}}
function storeSet(k,v){try{localStorage.setItem(k,v)}catch(e){}}
function storeRemove(k){try{localStorage.removeItem(k)}catch(e){}}
function val(id,d=""){const el=byId(id);return el?el.value:d}
function checked(id){const el=byId(id);return !!(el&&el.checked)}
function setVal(id,v){const el=byId(id);if(el)el.value=v}
function setText(id,v){const el=byId(id);if(el)el.textContent=v}
function setHtml(id,v){const el=byId(id);if(el)el.innerHTML=v}
function setStatusLog(v){setHtml("domainOpsLog",v);setHtml("adminOpsLog",v)}
function on(id,event,fn){const el=byId(id);if(el)el.addEventListener(event,fn)}
function esc(s){return String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function fmt(ts){return ts?new Date(Number(ts)).toLocaleString():""}
function bytes(n){n=Number(n||0);if(n<1024)return n+" B";if(n<1048576)return (n/1024).toFixed(1)+" KB";if(n<1073741824)return (n/1048576).toFixed(1)+" MB";return (n/1073741824).toFixed(2)+" GB"}
function errText(e){const m=e&&e.message?e.message:String(e||"请求失败");if(m==="unauthorized")return "访问密钥错误、已过期或此 token 已被禁用。数据没有丢失，请重新输入正确密钥。";return m}
function toast(message,type="ok",title="状态",ms=3600){let stack=byId("toastStack");if(!stack){stack=document.createElement("div");stack.id="toastStack";stack.className="toastStack";document.body.appendChild(stack)}const node=document.createElement("div");node.className=`toast ${type}`;node.innerHTML=`${title?`<b>${esc(title)}</b>`:""}<div>${esc(message)}</div>`;stack.appendChild(node);while(stack.children.length>5)stack.firstElementChild.remove();if(ms)window.setTimeout(()=>closeToast(node),ms);return node}
function closeToast(node){if(!node||!node.isConnected)return;node.style.animation="toastOut .16s ease forwards";window.setTimeout(()=>node.remove(),170)}
async function runButton(btn,busyText,fn,successText){if(btn&&btn.dataset.busy==="1")return false;const wasDisabled=btn?btn.disabled:false;if(btn){btn.dataset.busy="1";btn.classList.add("isBusy");btn.disabled=true}const busy=busyText?toast(busyText,"busy","正在处理",0):null;try{const result=await fn();if(result!==false&&successText){const msg=typeof successText==="function"?successText(result):successText;toast(msg||"操作完成","ok","完成")}return result}catch(e){toast(errText(e),"err","操作失败");return false}finally{if(busy)closeToast(busy);if(btn){btn.dataset.busy="";btn.classList.remove("isBusy");btn.disabled=wasDisabled}}}
function dnsResultToast(message,ok=true,title="DNS检查结果"){const node=toast(message,ok?"ok":"err",title,9000);node.classList.add("dnsResult");return node}
async function runDnsAction(fn){try{return await fn()}catch(e){dnsResultToast("DNS检查失败："+errText(e),false,"DNS检查失败");return false}}
function statusIcon(ok,warn=false){return warn?"⚠":(ok?"✓":"✕")}
function statusClass(ok,warn=false){return warn?"warn":(ok?"ok":"bad")}
function statusIconHtml(ok,warn=false,cls="statusIcon"){return `<span class="${cls} ${statusClass(ok,warn)}">${statusIcon(ok,warn)}</span>`}
function statusTitle(label,ok,warn=false){return `${statusIconHtml(ok,warn)}${esc(label)}`}
function setLiveState(state,label){const el=byId("liveStatus");if(!el)return;el.dataset.state=state||"idle";el.textContent=label||""}
function valueDomain(value){const v=String(value||"").toLowerCase();const at=v.lastIndexOf("@");return at>=0?v.slice(at+1):v}
function domainMatchesScope(value,domain){const scope=String(domain||"").toLowerCase(),host=valueDomain(value);return !!scope&&!!host&&(host===scope||host.endsWith("."+scope))}
function headers(json=true){return json?{"content-type":"application/json","authorization":token}:{"authorization":token}}
async function api(path,opt={}){
const controller=new AbortController(),timeout=String(path).includes("/changes")?35000:15000,timer=setTimeout(()=>controller.abort(),timeout);
try{const res=await fetch(path,{...opt,signal:controller.signal,headers:{...headers(!(opt&&opt.raw)),...(opt.headers||{})}});const data=await res.json().catch(()=>({}));if(!res.ok||data.code>=400)throw new Error(data.message||"请求失败");return data}
catch(e){if(e?.message&&e.message!=="Failed to fetch"&&e.name!=="AbortError")throw e;setLiveState(navigator.onLine?"error":"offline",navigator.onLine?"连接异常":"网络已断开");throw new Error(e?.name==="AbortError"?"请求超时":"无法连接到服务")}
finally{clearTimeout(timer)}}
async function dangerFlow(steps){return new Promise(resolve=>{let i=0,last="";const modal=byId("dangerModal"),title=byId("dangerTitle"),text=byId("dangerText"),input=byId("dangerInput"),ok=byId("dangerConfirm"),cancel=byId("dangerCancel");if(!modal||!title||!text||!input||!ok||!cancel)return resolve(false);function close(v){modal.classList.add("hidden");ok.onclick=null;cancel.onclick=null;input.onkeydown=null;resolve(v)}function show(){const s=steps[i];title.textContent=s.title;text.innerHTML=s.text;ok.textContent=s.button||"确认";input.value="";input.placeholder=s.placeholder||"";input.classList.toggle("hidden",!s.requireText);setTimeout(()=>s.requireText&&input.focus(),30)}cancel.onclick=()=>close(false);ok.onclick=()=>{const s=steps[i];if(s.requireText&&input.value.trim()!==s.requireText){toast("确认文本不匹配，操作已取消。","err","已取消");return close(false)}last=input.value.trim();i++;if(i>=steps.length)return close(last||true);show()};input.onkeydown=e=>{if(e.key==="Enter")ok.click()};modal.classList.remove("hidden");show()})}
let token=storeGet(TOKEN_KEY),currentEmail="",currentMessageId="",messages=[],aliases=[],selectedIds=new Set();
let aliasPage=1,aliasPageSize=50,aliasTotal=0,aliasQuery="",aliasTimer=0,aliasesLoading=false,aliasesSignature="";
let mailPage=1,mailPageSize=50,mailTotal=0,mailTimer=0,messagesLoading=false,messageIds=[],lastLiveToastAt=0,lastLiveErrorAt=0,lastLatest=0,lastDomainLatest=0,liveLoopStarted=false;
let domainPage=1,domainPageSize=20,domainTotal=0;
let dnsCountdownTimer=0;
let domainInfoCache={},currentRole="",canAddRootDomains=false;
let guideManuallyShown=false;
window.__ferretGuideHidden=false;
setVal("token",token);
function setTheme(v,silent=false){const theme=v==="dark"?"dark":"light";document.documentElement.dataset.theme=theme;storeSet("ferret_mail_theme",theme);setText("themeToggle",theme==="dark"?"浅色":"深色");if(!silent)toast(`已切换到${theme==="dark"?"深色":"浅色"}模式`,"ok","显示模式")}
function setVisual(v,silent=false){const allowed=new Set(["skyline","moyu","minimal"]),visual=allowed.has(v)?v:"skyline";document.documentElement.dataset.visual=visual;storeSet("ferret_mail_visual",visual);setVal("visualTheme",visual);if(!silent)toast("浅色主题已更新","ok","显示模式")}
setTheme(storeGet("ferret_mail_theme")||"light",true);
setVisual(storeGet("ferret_mail_visual")||"skyline",true);
function rootForDomain(d){d=String(d||"").toLowerCase();if(d===BASE_DOMAIN||d.endsWith("."+BASE_DOMAIN))return BASE_DOMAIN;const info=domainInfoCache[d]||{};return info.rootDomain||d}
function mxName(d){const root=rootForDomain(d);if(d===root)return "@";const suffix="."+root;return d.endsWith(suffix)?d.slice(0,-suffix.length):d}
function currentServerIp(){const h=location.hostname||"";return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)?h:PUBLIC_IP}
function dnsText(d){const info=domainInfoCache[d]||{},root=rootForDomain(d),name=info.mxName||mxName(d),mailHost=info.mxServer||("mail."+root),ip=info.mailAValue||currentServerIp();return `Cloudflare 配置方式\n\n目标域名\n${d}\n\n在 Cloudflare 后台打开 DNS 记录页，添加以下记录：\n\n1. MX 记录\nType: MX\nName: ${name}\nMail server: ${mailHost}\nPriority: 10\n\n2. A 记录\nType: A\nName: mail\nIPv4 address: ${ip}\nProxy status: DNS only / 灰云\n\n重要：A 记录不要开启代理。完成后等待 1-5 分钟，再用 a@${d} 测试收验证码。`}
function guideVisible(){const box=byId("cloudflareGuideBox");return !!(box&&!box.classList.contains("hidden")&&!box.classList.contains("guideHiddenByStatus"))}
function updateGuideButtons(){const visible=guideVisible();$$('[data-access-action="guide"]').forEach(btn=>{btn.textContent=visible&&guideManuallyShown?"隐藏Cloudflare配置":"查看Cloudflare配置"})}
function updateGuideBodyToggle(){const box=byId("cloudflareGuideBox"),btn=byId("toggleCloudflareGuideBody")||$("[data-guide-body-toggle]");if(box&&btn)btn.textContent=box.classList.contains("guideBodyCollapsed")?"展开正文":"收起正文"}
function setGuideShown(show,opt={}){const box=byId("cloudflareGuideBox");if(!box)return;if(show){box.classList.remove("guideHiddenByStatus");if(opt.open!==false)box.classList.remove("guideBodyCollapsed")}else{box.classList.add("guideHiddenByStatus");box.classList.add("guideBodyCollapsed")}updateGuideBodyToggle();updateGuideButtons()}
function showDns(d,opt={}){setText("cloudflareGuideDomain",`当前配置域名：${d}`);setText("dnsTips",dnsText(d));if(opt.force!==false){window.__ferretGuideHidden=false;guideManuallyShown=opt.manual!==false;setGuideShown(true,{open:opt.open!==false})}}
function hideDnsGuide(){guideManuallyShown=false;window.__ferretGuideHidden=true;setGuideShown(false,{open:false})}
document.addEventListener("click",e=>{const btn=e.target.closest("[data-guide-hide]");if(btn){e.preventDefault();e.stopPropagation();hideDnsGuide()}});
document.addEventListener("click",e=>{const btn=e.target.closest("[data-guide-body-toggle]");if(btn){e.preventDefault();const box=byId("cloudflareGuideBox");if(!box)return;box.classList.toggle("guideBodyCollapsed");updateGuideBodyToggle()}});
function applyGuideDefault(){if(guideManuallyShown&&!window.__ferretGuideHidden)updateGuideButtons();else setGuideShown(false,{open:false})}
function fallbackCopyText(value){const ta=document.createElement("textarea");ta.value=String(value||"");ta.setAttribute("readonly","");ta.style.position="fixed";ta.style.left="-9999px";ta.style.top="0";ta.style.opacity="0";document.body.appendChild(ta);ta.focus();ta.select();ta.setSelectionRange(0,ta.value.length);let ok=false;try{ok=document.execCommand&&document.execCommand("copy")}catch(e){ok=false}ta.remove();return !!ok}
async function copyText(value,success="已复制到剪贴板"){if(!value){toast("没有可复制内容","err","无法复制");return false}try{if(navigator.clipboard&&navigator.clipboard.writeText){await navigator.clipboard.writeText(value);toast(success,"ok","复制成功");return true}}catch(e){}if(fallbackCopyText(value)){toast(success,"ok","复制成功");return true}toast("复制失败，请手动选择内容。","err","复制失败");return false}
function aliasValue(){const v=val("aliasInput").trim().toLowerCase();if(!v)return "";return v.includes("@")?v:v+"@"+DOMAIN}
function localPart(value){return String(value||"").split("@")[0].toLowerCase().replace(/[^a-z0-9._+-]/g,"").slice(0,64)}
function pad(n,width){return String(n).padStart(width,"0")}
function today(){const d=new Date();return `${d.getFullYear()}${pad(d.getMonth()+1,2)}${pad(d.getDate(),2)}`}
function rand(len){const chars="abcdefghijklmnopqrstuvwxyz0123456789";let out="";for(let i=0;i<len;i++)out+=chars[Math.floor(Math.random()*chars.length)];return out}
const rules=[{id:"seq",name:"序列号",tpl:"{base}{n:3}"},{id:"dash",name:"短横线序号",tpl:"{base}-{n:3}"},{id:"dot",name:"点分序号",tpl:"{base}.{n:3}"},{id:"plus",name:"Plus 序号",tpl:"{base}+{n:3}"},{id:"date",name:"日期序号",tpl:"{date}-{base}-{n:3}"},{id:"random",name:"随机后缀",tpl:"{base}-{rand:6}"},{id:"custom",name:"自定义规则",tpl:"{base}-{n:3}"}];
function templateFor(rule){return rule.id==="custom"?(val("customTemplate").trim()||rule.tpl):rule.tpl}
function renderTpl(tpl,n,idx,base){return tpl.replace(/\{base\}/g,base).replace(/\{date\}/g,today()).replace(/\{i\}/g,idx).replace(/\{n(?::(\d+))?\}/g,(_,w)=>w?pad(n,Number(w)):String(n)).replace(/\{rand(?::(\d+))?\}/g,(_,w)=>rand(Math.min(Number(w||6),16)))}
function generatedAliases(limit){const rule=rules.find(r=>r.id===val("ruleSelect"))||rules[0],base=localPart(val("batchBase").trim());if(!base)throw new Error("请先输入批量前缀");const start=Number(val("batchStart","1")||1),count=Math.max(1,Math.min(Number(val("batchCount","1")||1),10000)),tpl=templateFor(rule),out=[];for(let i=0;i<Math.min(count,limit||count);i++){const part=localPart(renderTpl(tpl,start+i,i,base));if(!part)throw new Error("生成结果为空，请调整规则");out.push(part)}return out}
function renderGenerator(){if(!byId("ruleSelect"))return;try{const rawBase=val("batchBase").trim();if(!rawBase){setHtml("batchPreview",'<div class="empty">未输入批量前缀。</div>');setHtml("rulePreviewGrid","");setText("batchErr","");return}const preview=generatedAliases(20).map(x=>x+"@"+DOMAIN);setHtml("batchPreview",`<b>本次预览 ${preview.length} 个</b><br>${preview.map(esc).join("<br>")}`);setText("batchErr","");const base=localPart(rawBase),start=Number(val("batchStart","1")||1);setHtml("rulePreviewGrid",rules.filter(r=>r.id!=="custom").map(r=>{const arr=[0,1,2].map(i=>localPart(renderTpl(r.tpl,start+i,i,base))+"@"+DOMAIN);return `<div class="rulePreview"><b>${esc(r.name)}</b><div>${arr.map(esc).join(" · ")}</div></div>`}).join(""))}catch(e){setText("batchErr",errText(e))}}
function selectedList(){return Array.from(selectedIds).map(Number)}
function latestAliasItem(){return aliases.reduce((best,item)=>Number(item.latest||0)>Number(best?.latest||0)?item:best,null)}
function updateAliasPager(){const pages=Math.max(1,Math.ceil(aliasTotal/aliasPageSize));const info=`${aliasTotal} 个别名 · 第 ${Math.min(aliasPage,pages)} / ${pages} 页`;setText("aliasPageInfo",info);setText("aliasListSummary",`${aliasTotal} 个`);const prev=byId("aliasPrev"),next=byId("aliasNext");if(prev)prev.disabled=aliasPage<=1;if(next)next.disabled=aliasPage>=pages}
function updateMailPager(){const pages=Math.max(1,Math.ceil(mailTotal/mailPageSize));setText("mailPageInfo",`${mailTotal} 封邮件 · 第 ${Math.min(mailPage,pages)} / ${pages} 页 · 已选 ${selectedIds.size}`);const prev=byId("mailPrev"),next=byId("mailNext");if(prev)prev.disabled=mailPage<=1;if(next)next.disabled=mailPage>=pages}
function clearMailboxView(message="当前邮件视图已清空。"){currentEmail="";currentMessageId="";messages=[];messageIds=[];selectedIds.clear();mailTotal=0;mailPage=1;lastLatest=0;storeRemove(CURRENT_KEY);setText("currentTitle","请选择别名");setText("currentMeta","选择别名查看邮件");renderMessages();setHtml("mailList",`<div class="empty">${esc(message)}</div>`);setHtml("mailDetail",'<div class="empty">选择一封邮件查看内容。</div>')}
async function aliasExists(email){email=String(email||"").trim().toLowerCase();if(!email||valueDomain(email)!==DOMAIN)return false;const local=aliases.some(a=>String(a.email||"").toLowerCase()===email);if(local)return true;if(aliasTotal&&aliasTotal<=aliases.length)return false;const qs=new URLSearchParams({domain:DOMAIN,page:"1",pageSize:"10",q:email});const data=await api("/ui-api/aliases?"+qs.toString());return (data.data||[]).some(a=>String(a.email||"").toLowerCase()===email)}
async function restoreRememberedMailbox(){const remembered=String(storeGet(CURRENT_KEY)||"").trim().toLowerCase();if(currentEmail||!remembered)return false;if(valueDomain(remembered)!==DOMAIN){clearMailboxView("之前打开的别名不属于当前域名，当前邮件列表为空。");return false}if(!(await aliasExists(remembered).catch(()=>false))){clearMailboxView("之前打开的别名已不存在，当前邮件列表为空。");return false}await loadMessages(remembered);return true}
function aliasShareUrl(path){return path?location.origin+path:""}
function renderAliases(){updateAliasPager();setHtml("aliases",aliases.map(a=>`<div class="alias ${a.email===currentEmail?'active':''}"><button class="aliasOpen" data-email="${esc(a.email)}" title="${esc(a.email)}"><div class="email">${esc(a.email)}</div><div class="meta">${a.count||0} 封${a.latest?' · '+fmt(a.latest):''}</div></button><div class="toolbar aliasActions"><button class="secondary" data-share-alias="${esc(a.email)}">${a.shareEnabled?'复制':'链接'}</button>${a.shareEnabled?`<button class="secondary" data-reset-share="${esc(a.email)}">重置</button><button class="softDanger" data-disable-share="${esc(a.email)}">禁用</button>`:''}<button class="softDanger" data-delete-alias="${esc(a.email)}">删除</button></div></div>`).join("")||'<div class="empty">暂无别名，新邮件到达时会自动创建。</div>');$$(".aliasOpen").forEach(el=>el.addEventListener("click",()=>loadMessages(el.dataset.email).catch(e=>toast(errText(e),"err","打开失败"))));$$("button[data-share-alias]").forEach(el=>el.addEventListener("click",e=>runButton(e.currentTarget,"正在生成或复制接码链接...",()=>copyAliasShare(el.dataset.shareAlias),msg=>msg)));$$("button[data-reset-share]").forEach(el=>el.addEventListener("click",e=>runButton(e.currentTarget,"正在重置接码链接...",()=>resetAliasShare(el.dataset.resetShare),msg=>msg)));$$("button[data-disable-share]").forEach(el=>el.addEventListener("click",e=>runButton(e.currentTarget,"正在禁用接码链接...",()=>disableAliasShare(el.dataset.disableShare),msg=>msg)));$$("button[data-delete-alias]").forEach(el=>el.addEventListener("click",e=>runButton(e.currentTarget,"正在删除别名...",()=>deleteAlias(el.dataset.deleteAlias),msg=>msg)))}
async function setAliasShare(email,opt={}){const res=await api("/ui-api/alias-share-token",{method:"POST",body:JSON.stringify({domain:DOMAIN,email,...opt})});const data=res.data||{};if(data.enabled){const url=data.url||aliasShareUrl(data.path);await copyText(url,opt.reset?"新的接码链接已复制":"接码链接已复制")}await loadAliases();return data.enabled?(opt.reset?"已重置并复制接码链接":"已生成/复制接码链接"):"已禁用接码链接"}
async function copyAliasShare(email){return setAliasShare(email,{enabled:true})}
async function resetAliasShare(email){const ok=await dangerFlow([{title:"重置接码链接",text:`${esc(email)} 的旧链接会立即失效。`,button:"重置链接"}]);if(!ok)return false;return setAliasShare(email,{enabled:true,reset:true})}
async function disableAliasShare(email){const ok=await dangerFlow([{title:"禁用接码链接",text:`关闭后，现有链接将无法再查看 ${esc(email)} 的验证码。别名和邮件不受影响。`,button:"禁用链接"}]);if(!ok)return false;return setAliasShare(email,{enabled:false})}
async function exportAliasShareLinks(){if(!aliasTotal)throw new Error("当前域名没有别名可导出");const ok=await dangerFlow([{title:"导出接码链接",text:`将导出 ${aliasTotal} 个别名的只读接码链接；持有链接的人可查看对应别名的邮件验证码。`,button:"导出 TXT"}]);if(!ok)return false;const res=await fetch("/ui-api/alias-share-export",{method:"POST",headers:headers(true),body:JSON.stringify({domain:DOMAIN})});if(!res.ok){const data=await res.json().catch(()=>({}));throw new Error(data.message||"导出失败")}const blob=await res.blob();const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`alias-code-links-${DOMAIN}.txt`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);await loadAliases();return `已导出 ${res.headers.get("X-Export-Count")||aliasTotal} 个别名接码链接`}
function renderMessages(){
updateMailPager();
if(!messages.length){setHtml("mailList",`<div class="empty">${currentEmail||val("mailScope")==="domain"?"还没有符合条件的邮件。":"选择左侧别名开始收件。"}</div>`);return}
setHtml("mailList",messages.map(m=>{const id=String(m.id),flags=[];if(!m.isRead)flags.push('<span class="flag hot">未读</span>');if(m.starred)flags.push('<span class="flag">星标</span>');if(m.pinned)flags.push('<span class="flag">置顶</span>');if(m.hasLink)flags.push('<span class="flag">链接</span>');const codeBtn=m.code?`<button type="button" class="code codeQuickBtn" data-copy-code="${esc(m.code)}" title="点击复制验证码" aria-label="点击复制验证码 ${esc(m.code)}">复制 ${esc(m.code)}</button>`:"";return `<div class="mail ${m.isRead?'':'unread'} ${id===String(currentMessageId)?'active':''}" data-id="${id}"><input class="mailCheck" type="checkbox" data-id="${id}" ${selectedIds.has(id)?'checked':''}><div class="mailMetaLine"><div class="subject">${esc(m.subject||'(无标题)')} ${codeBtn}</div><div class="preview">${esc(m.fromEmail||'')} · ${fmt(m.receivedAt)} · ${esc(m.toEmail||'')}</div><div class="preview">${esc((m.text||m.content||'').slice(0,150))}</div><div class="mailFlags">${flags.join("")}</div></div></div>`}).join(""));
$$("button[data-copy-code]").forEach(el=>el.addEventListener("click",e=>{e.stopPropagation();copyText(el.dataset.copyCode,"验证码已复制")}));
$$(".mail[data-id]").forEach(el=>el.addEventListener("click",e=>{if(e.target.closest("button,a,input"))return;showMail(Number(el.dataset.id),el).catch(err=>toast(errText(err),"err","打开失败"))}));
$$(".mailCheck").forEach(el=>el.addEventListener("click",e=>{e.stopPropagation();const id=String(el.dataset.id);el.checked?selectedIds.add(id):selectedIds.delete(id);updateMailPager()}))
}
async function loadAliases(selectEmail="",opt={}){if(aliasesLoading)return false;aliasesLoading=true;try{const qs=new URLSearchParams({domain:DOMAIN,page:String(aliasPage),pageSize:String(aliasPageSize),q:aliasQuery});const data=await api("/ui-api/aliases?"+qs.toString());setText("loginErr","");aliases=data.data||[];aliasTotal=data.total||0;aliasPage=data.page||aliasPage;aliasPageSize=data.pageSize||aliasPageSize;if(aliasPage>1&&!aliases.length){aliasPage--;aliasesLoading=false;return loadAliases(selectEmail,opt)}lastDomainLatest=Math.max(lastDomainLatest,...aliases.map(a=>Number(a.latest||0)),0);const sig=aliases.map(a=>`${a.email}:${a.count||0}:${a.latest||0}`).join("|");const changed=aliasesSignature&&sig!==aliasesSignature;aliasesSignature=sig;renderAliases();if(currentEmail&&(valueDomain(currentEmail)!==DOMAIN||!await aliasExists(currentEmail).catch(()=>false))){clearMailboxView("当前别名已不存在，邮件列表已同步清空。");renderAliases()}if(changed&&opt.auto){const latest=latestAliasItem();if(latest)toast(`检测到新邮件或别名更新：${latest.email}`,"ok","自动同步")}if(selectEmail)await loadMessages(selectEmail);return true}finally{aliasesLoading=false}}
function mailQueryParams(){const qs=new URLSearchParams({domain:DOMAIN,page:String(mailPage),pageSize:String(mailPageSize),q:val("mailSearch").trim(),code:val("mailCodeSearch").trim(),dateFrom:val("mailDateFrom"),dateTo:val("mailDateTo")});if(val("mailScope","alias")==="alias"&&currentEmail)qs.set("email",currentEmail);if(checked("filterCode"))qs.set("hasCode","1");if(checked("filterLink"))qs.set("hasLink","1");if(checked("filterUnread"))qs.set("unread","1");if(checked("filterToday"))qs.set("today","1");if(checked("filterStarred"))qs.set("starred","1");if(checked("filterPinned"))qs.set("pinned","1");return qs}
async function loadMessages(email="",opt={}){if(email){currentEmail=email;storeSet(CURRENT_KEY,email);mailPage=opt.keepPage?mailPage:1}if(val("mailScope","alias")==="alias"&&!currentEmail){setHtml("mailList",'<div class="empty">选择左侧别名开始收件。</div>');return false}if(messagesLoading)return false;messagesLoading=true;try{const previousIds=messageIds.slice();if(!opt.auto)setText("currentMeta","正在加载...");if(currentEmail)setText("currentTitle",currentEmail);$$(".alias").forEach(el=>el.classList.toggle("active",el.querySelector(".aliasOpen")?.dataset.email===currentEmail));const data=await api("/ui-api/messages?"+mailQueryParams().toString());messages=data.data||[];mailTotal=data.total||0;mailPage=data.page||mailPage;mailPageSize=data.pageSize||mailPageSize;messageIds=messages.map(m=>String(m.id));lastLatest=Math.max(lastLatest,...messages.map(m=>Number(m.receivedAt||0)),0);lastDomainLatest=Math.max(lastDomainLatest,lastLatest);const previousSet=new Set(previousIds);const newItems=opt.auto&&previousIds.length?messages.filter(m=>!previousSet.has(String(m.id))):[];setText("currentMeta",`${mailTotal} 封邮件`);renderMessages();if(newItems.length){await showMail(newItems[0].id,$(`.mail[data-id="${newItems[0].id}"]`));notifyNewMail(newItems[0],newItems.length)}else if(messages.length&&!opt.preserve){await showMail(messages[0].id,$(".mail[data-id]"))}else if(currentMessageId){const active=$(`.mail[data-id="${currentMessageId}"]`);if(active)active.classList.add("active")}if(!messages.length){currentMessageId="";setHtml("mailDetail",'<div class="empty">还没有邮件。</div>')}return true}finally{messagesLoading=false}}
function emailFrameDocument(raw,text){let content=String(raw||"");try{const parsed=new DOMParser().parseFromString(content,"text/html");content=parsed.body?.innerHTML||content}catch(e){}if(!content.trim())content=`<pre>${esc(text||"")}</pre>`;return `<!doctype html><html><head><meta charset="utf-8"><meta name="color-scheme" content="light"><style>:root{color-scheme:light}*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:#fff!important;color:#1b3449!important}body{padding:28px;font:15px/1.75 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;overflow-wrap:anywhere}.emailContent,.emailContent :where(p,div,span,td,th,li,blockquote,pre,h1,h2,h3,h4,h5,h6){color:#1b3449!important;background-color:transparent!important}.emailContent a{color:#087bc8!important;text-decoration-color:#8fd2fb!important;text-underline-offset:3px}.emailContent img{max-width:100%;height:auto}.emailContent table{max-width:100%!important;border-collapse:collapse}.emailContent td,.emailContent th{max-width:100%}.emailContent blockquote{margin-left:0;padding:10px 16px;border-left:3px solid #43aff0;background:#eef8ff!important}.emailContent pre{white-space:pre-wrap;background:#f4f9fd!important;padding:14px;border:1px solid #d7ebf8;border-radius:10px}.emailContent hr{border:0;border-top:1px solid #d7ebf8}</style></head><body><div class="emailContent">${content}</div></body></html>`}
function renderDetailBody(m,mode){const box=byId("mailBodyBox");if(!box)return;if(mode==="text")box.innerHTML=`<div class="plainView">${esc(m.text||"")}</div>`;else if(mode==="raw")box.innerHTML=`<div class="plainView">${esc(m.raw||"")}</div>`;else if(mode==="headers")box.innerHTML=`<div class="plainView">${(m.headers||[]).map(h=>esc(h.name+": "+h.value)).join("\\n")}</div>`;else box.innerHTML=`<iframe class="frame" title="邮件正文" sandbox="allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer"></iframe>`,box.querySelector("iframe").srcdoc=emailFrameDocument(m.html,m.text);$$(".tabBtn").forEach(b=>b.classList.toggle("active",b.dataset.mode===mode))}
async function setMessageState(ids,values){const res=await api("/ui-api/message-state",{method:"POST",body:JSON.stringify({ids,...values})});return res.changed||0}
async function showMail(id,el){currentMessageId=String(id);$$(".mail").forEach(x=>x.classList.remove("active"));if(el)el.classList.add("active");setHtml("mailDetail",'<div class="empty">正在打开邮件...</div>');const res=await api(`/ui-api/message?id=${id}`);const m=res.data;await setMessageState([id],{isRead:true}).catch(()=>{});const listItem=messages.find(item=>String(item.id)===String(id));if(listItem&&!listItem.isRead){listItem.isRead=true;renderMessages()}const links=m.links||[],firstLink=links[0]?.url||"";const attaches=(m.attachments||[]).map(a=>`<div class="attach"><div><b>${esc(a.filename)}</b><div class="muted">${esc(a.contentType)} · ${bytes(a.size)}${a.downloadable?'':' · 超出保存上限'}</div></div><div class="toolbar">${a.downloadable?`<button class="secondary" data-attach="${a.id}">下载</button>`:''}</div></div>`).join("");const actions=links.map(x=>`<a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.label||'打开链接')}</a>`).join("");setHtml("mailDetail",`<div class="detailHeader"><div><h2>${esc(m.subject||'(无标题)')} ${m.code?`<span class="code">${esc(m.code)}</span>`:''}</h2><div class="muted">发件人：${esc(m.fromEmail||'')}<br>收件人：${esc(m.toEmail||'')}<br>${fmt(m.receivedAt)}</div></div><div class="toolbar">${m.code?`<button class="secondary" id="copyCode">复制验证码</button>`:''}${firstLink?'<button class="secondary" id="copyFirstLink">复制登录链接</button>':''}<button class="secondary" id="copyFullText">复制全文</button><button class="secondary" id="toggleStar">${m.starred?'取消星标':'星标'}</button><button class="secondary" id="togglePin">${m.pinned?'取消置顶':'置顶'}</button><button class="danger" id="deleteMail">删除</button></div></div>${actions?`<div class="actions">${actions}</div>`:''}${attaches?`<div class="attachList">${attaches}</div>`:''}<div class="tabs"><button class="secondary tabBtn active" data-mode="html">HTML</button><button class="secondary tabBtn" data-mode="text">纯文本</button><button class="secondary tabBtn" data-mode="raw">源码</button><button class="secondary tabBtn" data-mode="headers">邮件头</button></div><div id="mailBodyBox"></div>`);on("copyCode","click",()=>copyText(m.code,"验证码已复制"));on("copyFirstLink","click",()=>copyText(firstLink,"登录链接已复制"));on("copyFullText","click",()=>copyText(m.text||m.raw||"","全文已复制"));on("deleteMail","click",e=>runButton(e.currentTarget,"正在删除邮件...",()=>deleteCurrentMail(m.id),msg=>msg));on("toggleStar","click",e=>runButton(e.currentTarget,"正在更新星标...",async()=>{await setMessageState([m.id],{starred:!m.starred});await loadMessages("",{preserve:true,keepPage:true});return !m.starred?"已星标":"已取消星标"},msg=>msg));on("togglePin","click",e=>runButton(e.currentTarget,"正在更新置顶...",async()=>{await setMessageState([m.id],{pinned:!m.pinned});await loadMessages("",{preserve:true,keepPage:true});return !m.pinned?"已置顶":"已取消置顶"},msg=>msg));$$(".tabBtn").forEach(b=>b.addEventListener("click",()=>renderDetailBody(m,b.dataset.mode)));$$("button[data-attach]").forEach(b=>b.addEventListener("click",()=>downloadAttachment(b.dataset.attach)));renderDetailBody(m,"html");return true}
function tidyMailDetail(){const detail=byId("mailDetail"),toolbar=detail?.querySelector(".detailHeader .toolbar");if(!detail||!toolbar)return;const frame=detail.querySelector("iframe");if(frame&&!frame.dataset.scrollGuard){frame.dataset.scrollGuard="1";frame.setAttribute("tabindex","-1");frame.addEventListener("load",()=>{frame.blur();detail.scrollTop=0;setTimeout(()=>detail.scrollTop=0,0)},{once:true})}if(!toolbar.querySelector(".detailMore")){const buttons=["toggleStar","togglePin","deleteMail"].map(byId).filter(Boolean);if(buttons.length){const more=document.createElement("details");more.className="quickMenu detailMore";more.innerHTML='<summary>更多</summary><div class="quickMenuPanel"></div>';const panel=more.querySelector(".quickMenuPanel");buttons.forEach(button=>panel.appendChild(button));toolbar.appendChild(more)}}const reset=()=>{detail.scrollTop=0};reset();requestAnimationFrame(reset);setTimeout(reset,120)}
const mailDetailObserver=new MutationObserver(tidyMailDetail);if(byId("mailDetail"))mailDetailObserver.observe(byId("mailDetail"),{childList:true,subtree:true});
async function downloadAttachment(id){const res=await fetch(`/ui-api/attachment?id=${encodeURIComponent(id)}`,{headers:headers(false)});if(!res.ok)throw new Error("附件下载失败");const blob=await res.blob();const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="attachment";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
async function deleteCurrentMail(id){const ok=await dangerFlow([{title:"删除邮件",text:"确定删除这封邮件？此操作不可恢复。",button:"删除"}]);if(!ok)return false;const res=await api("/ui-api/delete-message",{method:"POST",body:JSON.stringify({id})});selectedIds.delete(String(id));currentMessageId="";await loadMessages("",{preserve:true,keepPage:true});await loadAliases();return `已删除 ${res.deleted||0} 封邮件。`}
async function bulkMail(action){const ids=selectedList();if(!ids.length){toast("请先选择邮件。","err","未选择");return false}if(action==="delete"){const ok=await dangerFlow([{title:"删除所选邮件",text:`确定删除 ${ids.length} 封邮件？此操作不可恢复。`,button:"删除"}]);if(!ok)return false}const res=await api("/ui-api/messages-bulk",{method:"POST",body:JSON.stringify({ids,action})});selectedIds.clear();await loadMessages("",{preserve:true,keepPage:true});await loadAliases();return `已处理 ${res.changed||0} 封邮件。`}
async function copySelectedCodes(){const rows=messages.filter(m=>selectedIds.has(String(m.id))&&m.code);if(!rows.length){toast("已选邮件里没有识别到验证码。","err","无验证码");return false}await copyText(rows.map(m=>`${m.toEmail} ${m.code}`).join("\\n"),"已复制所选验证码");return true}
async function clearAliasMessages(){if(!currentEmail)throw new Error("请先选择别名");const ok=await dangerFlow([{title:"清空别名邮件",text:`将删除 ${esc(currentEmail)} 的全部邮件，但保留别名。请输入完整邮箱确认。`,requireText:currentEmail,placeholder:currentEmail,button:"清空邮件"}]);if(!ok)return false;const res=await api("/ui-api/clear-alias-messages",{method:"POST",body:JSON.stringify({email:currentEmail,confirm:currentEmail})});selectedIds.clear();currentMessageId="";await loadMessages("",{preserve:true});await loadAliases();return `已清空 ${res.deleted||0} 封邮件。`}
async function clearDomainMessages(){const scope=DOMAIN;const ok=await dangerFlow([{title:"清空域名邮件",text:`将删除 ${esc(scope)} 下的全部邮件，但保留别名。请输入完整域名确认。`,requireText:scope,placeholder:scope,button:"清空邮件"}]);if(!ok)return false;const res=await api("/ui-api/clear-messages",{method:"POST",body:JSON.stringify({domain:scope,confirm:scope})});selectedIds.clear();currentMessageId="";messages=[];renderMessages();setHtml("mailDetail",'<div class="empty">已清空当前域名邮件。</div>');await loadAliases();return `已清空 ${res.deleted||0} 封邮件。`}
async function deleteAlias(email){const ok=await dangerFlow([{title:"删除别名",text:`确定从管理列表删除 ${esc(email)}？已有邮件会保留。`,button:"删除别名"}]);if(!ok)return false;const res=await api("/ui-api/delete-alias",{method:"POST",body:JSON.stringify({domain:DOMAIN,email,confirm:email})});if(currentEmail===email){currentEmail="";currentMessageId="";messages=[];messageIds=[];selectedIds.clear();storeRemove(CURRENT_KEY);setText("currentTitle","请选择别名");setText("currentMeta","选择别名查看邮件");setHtml("mailList","");setHtml("mailDetail",'<div class="empty">选择一封邮件查看内容。</div>')}await loadAliases();return `已删除 ${res.data.deleted||0} 个别名。`}
async function clearAllAliases(){const scope=DOMAIN;if(!aliasTotal){toast("当前没有别名。","busy","无需清空");return false}const ok=await dangerFlow([{title:"清空所有别名",text:`将删除 ${esc(scope)} 下的 ${aliasTotal} 个别名，但保留邮件。请输入完整域名确认。`,requireText:scope,placeholder:scope,button:"下一步"},{title:"确认批量删除",text:`请输入 <span class="dangerNote">清空别名</span>。`,requireText:"清空别名",placeholder:"清空别名",button:"清空别名"}]);if(!ok)return false;const res=await api("/ui-api/clear-aliases",{method:"POST",body:JSON.stringify({domain:scope,confirm:scope,phrase:"清空别名"})});currentEmail="";currentMessageId="";messages=[];messageIds=[];selectedIds.clear();aliasPage=1;storeRemove(CURRENT_KEY);setHtml("mailList","");setHtml("mailDetail",'<div class="empty">已清空当前域名别名。</div>');await loadAliases();return `已清空 ${res.deleted||0} 个别名。`}
function setAdminDrawer(open){const drawer=byId("adminDrawer");if(!drawer)return;drawer.classList.toggle("drawerClosed",!open);drawer.setAttribute("aria-hidden",open?"false":"true");document.body.classList.toggle("adminOpen",!!open);if(open)setTimeout(()=>byId("closeAdminDrawer")?.focus(),30)}
function setAdminVisible(show){$$(".adminOnly").forEach(el=>el.classList.toggle("hidden",!show));if(!show)setAdminDrawer(false)}
function setGlobalAdminVisible(show){$$(".globalAdminOnly").forEach(el=>el.classList.toggle("hidden",!show))}
function setAdminView(view){view=view||storeGet("ferret_admin_view","overview");if(view==="roots"&&!canAddRootDomains)view="domains";if(view==="ops"&&!canAddRootDomains)view="overview";storeSet("ferret_admin_view",view);$$("[data-admin-section]").forEach(el=>el.classList.toggle("hidden",el.dataset.adminSection!==view));$$("[data-admin-view]").forEach(el=>el.classList.toggle("active",el.dataset.adminView===view))}
function updateAdminScope(data){currentRole=data.role||"";canAddRootDomains=!!data.canAddRootDomains;const label=currentRole==="admin"?"全局管理员":(currentRole==="root"?"主域名管理员":"域名管理员");setText("adminScopeLine",`${label} · ${data.root||BASE_DOMAIN}`);setAdminView(storeGet("ferret_admin_view","overview"))}
function rememberDomainInfo(items){(items||[]).forEach(x=>{if(x&&x.domain)domainInfoCache[x.domain]=x})}
async function downloadDomainExport(type){const qs=new URLSearchParams({type,root:BASE_DOMAIN});const res=await fetch("/ui-api/domain-export?"+qs.toString(),{headers:headers(false)});if(!res.ok){const data=await res.json().catch(()=>({}));throw new Error(data.message||"导出失败")}const blob=await res.blob();const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`${type}-${BASE_DOMAIN}.txt`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);return "导出已开始"}
function renderDnsBulkResults(items){const rows=(items||[]).map(d=>`<div class="statusItem ${statusClass(d.ok)}"><div class="statusTitle">${statusTitle(`${d.domain}：${d.ok?'正常':'异常'}`,d.ok)}</div>${(d.checks||[]).map(x=>`<div class="muted">${statusIconHtml(x.ok)}${esc(x.name)}：${x.ok?'正常':'异常'} · ${esc(x.message||"")}</div>`).join("")}</div>`).join("");setHtml("dnsBulkLog",rows||"暂无检测结果。")}
async function checkDnsBulk(scope){const qs=new URLSearchParams({root:BASE_DOMAIN,scope});const res=await api("/ui-api/dns-check-bulk?"+qs.toString());const d=res.data||{},items=d.data||[],bad=items.filter(x=>!x.ok).length,msg=`已检测 ${d.checked||0} 个域名，${bad?bad+" 个异常":"全部正常"}${d.limited?"，结果已按上限截断":""}`;renderDnsBulkResults(items);dnsResultToast(msg,!bad,bad?"DNS检查发现异常":"DNS检查通过");return msg}
function bindDomainActionButtons(){ $$("[data-check-dns]").forEach(el=>el.addEventListener("click",e=>runButton(e.currentTarget,"正在进行DNS检查...",()=>runDnsAction(()=>{showDns(el.dataset.checkDns);return checkDns(el.dataset.checkDns)}))));$$("[data-token-domain]").forEach(el=>el.addEventListener("click",e=>runButton(e.currentTarget,"正在重置独立 Token...",()=>resetDomainToken(el.dataset.tokenDomain),"新 Token 已生成")));$$("[data-copy-token]").forEach(el=>el.addEventListener("click",()=>copyText(el.dataset.copyToken,"域名 Token 已复制")));$$("[data-copy-link]").forEach(el=>el.addEventListener("click",()=>copyText(location.origin+el.dataset.copyLink,"独立登录链接已复制")));$$("[data-delete-domain]").forEach(el=>el.addEventListener("click",e=>runButton(e.currentTarget,"正在准备删除确认...",()=>deleteManagedDomain(el.dataset.deleteDomain),msg=>msg)))}
function updateDomainPager(){const pages=Math.max(1,Math.ceil(domainTotal/domainPageSize));setText("domainPageInfo",`${domainTotal} 个域名 · 第 ${Math.min(domainPage,pages)} / ${pages} 页`);const prev=byId("domainPrev"),next=byId("domainNext");if(prev)prev.disabled=domainPage<=1;if(next)next.disabled=domainPage>=pages}
function renderRootTabs(items){const box=byId("rootTabs");if(!box)return;setHtml("rootTabs",(items||[]).map(x=>`<a class="secondary tabBtn ${x.active?'active':''}" href="${esc(x.path)}">${esc(x.domain)}</a>`).join("")||"")}
function renderRootTokenPanel(items){const box=byId("rootTokenList");if(!box)return;const roots=(items||[]).filter(x=>x&&x.domain);if(!roots.length){setHtml("rootTokenList",'<div class="empty">暂无主域名。</div>');return}const rows=roots.map(x=>{const token=x.token||"",status=`域名${x.enabled===false?"停用":"启用"} / Token ${x.tokenDisabled?"禁用":"启用"}`,canDeleteRoot=canAddRootDomains&&x.domain!==BASE_DOMAIN&&x.domain!==DEFAULT_ROOT_DOMAIN;return `<tr><td><b>${esc(x.domain)}</b><div class="muted">${esc(status)}${x.owner?` · ${esc(x.owner)}`:""}</div></td><td>${x.subdomainCount||0}</td><td>${x.aliasCount||0}</td><td>${x.mailCount||0}</td><td>${x.latest?fmt(x.latest):"暂无"}</td><td><div class="copyTokenLine">${token?esc(token):"未生成"}</div></td><td><div class="toolbar"><a class="secondary" href="${esc(x.path)}">进入后台</a><button class="secondary" data-copy-link="${esc(x.path)}">复制链接</button>${token?`<button class="secondary" data-copy-token="${esc(token)}">复制 Token</button>`:""}<button class="secondary" data-token-domain="${esc(x.domain)}">${token?"重置":"生成"} Token</button><button class="secondary" data-check-dns="${esc(x.domain)}">DNS检查</button>${canDeleteRoot?`<button class="danger" data-delete-domain="${esc(x.domain)}">删除主域名</button>`:""}</div></td></tr>`}).join("");setHtml("rootTokenList",`<div class="tableWrap"><table class="adminTable"><thead><tr><th>主域名</th><th>子域名</th><th>别名</th><th>邮件</th><th>最近收信</th><th>Token</th><th>操作</th></tr></thead><tbody>${rows}</tbody></table></div>`)}
function dnsCheckOk(dns,name){return !!((dns.checks||[]).find(x=>String(x.name||"").includes(name))||{}).ok}
function renderAccessStatus(d){
const dns=d.dns||{},connected=!!dns.ok,hasMail=Number(d.mails||0)>0,running=connected&&hasMail;
applyGuideDefault(connected);
const steps=[["MX",dnsCheckOk(dns,"MX")],["A记录",dnsCheckOk(dns,"A 记录")||dnsCheckOk(dns,"mail A")],["灰云",dnsCheckOk(dns,"灰云")],["测试收件",hasMail]];
const stepHtml=steps.map(([label,ok])=>`<span class="accessStep ${ok?'done':'todo'}">${statusIcon(ok,!ok)} ${esc(label)}</span>`).join("");
const title=running?"已接入，正常运行":(connected?"DNS已接入，等待测试收件":"等待接入，先完成 DNS");
const badge=running?"运行中":(connected?"DNS已通过":"未完成接入");
setHtml("adminAccessStatus",`<div class="accessCard ${connected?'ok':'wait'}"><div class="accessMain"><span class="accessTitle">${esc(title)}</span><span class="accessBadge">${esc(badge)}</span><div class="accessSteps">${stepHtml}</div></div><div class="toolbar accessToolbar"><button class="secondary" data-access-action="dns">DNS检查</button><button class="secondary" data-access-action="guide">查看Cloudflare配置</button><button class="secondary" data-access-action="domains">域名管理和接入</button></div></div>`);
$$("[data-access-action]").forEach(el=>el.addEventListener("click",()=>{const action=el.dataset.accessAction;if(action==="dns")setAdminView("dns");if(action==="domains")setAdminView("domains");if(action==="guide"){if(guideVisible()&&guideManuallyShown){hideDnsGuide()}else{showDns(BASE_DOMAIN,{manual:true,open:true});setAdminView("overview")}}}));
updateGuideButtons();
}
async function loadOverview(){
if(!ROOT_PAGE||!byId("overviewStats"))return;
const res=await api("/ui-api/admin/overview?root="+encodeURIComponent(BASE_DOMAIN));
const d=res.data||{};
renderAccessStatus(d);
setHtml("overviewStats",`<div class="stat"><span class="muted">域名</span><b>${d.domains||0}</b></div><div class="stat"><span class="muted">别名</span><b>${d.aliases||0}</b></div><div class="stat"><span class="muted">邮件</span><b>${d.mails||0}</b></div><div class="stat"><span class="muted">今日收信</span><b>${d.todayMails||0}</b></div><div class="stat"><span class="muted">密钥失败</span><b>${d.authFailedToday||0}</b></div><div class="stat"><span class="muted">数据库</span><b>${bytes(d.dbSize)}</b></div><div class="stat"><span class="muted">备份</span><b>${bytes(d.backupSize)}</b></div>`);
const service=d.service||{},components=service.components||{},componentLabels={http:"Web",smtp:"SMTP",database:"数据库",disk:"磁盘",backups:"备份"};
const serviceItems=Object.entries(componentLabels).map(([key,label])=>{const item=components[key]||{},ok=!!item.ok;return `<div class="monitorItem ${statusClass(ok,!ok)}">${statusIconHtml(ok,!ok,"monitorIcon")}<b>${esc(label)}：${ok?'正常':'异常'}</b><div class="muted">${esc(item.message||'')}</div></div>`}).join("");
const dns=d.dns||{};
const dnsItems=(dns.checks||[]).map(x=>`<div class="monitorItem ${statusClass(x.ok)}">${statusIconHtml(x.ok,false,"monitorIcon")}<b>${esc(x.name)}：${x.ok?'正常':'异常'}</b><div class="muted">${esc(x.message||'')}</div></div>`).join("")||`<div class="monitorItem warn">${statusIconHtml(false,true,"monitorIcon")}<b>DNS检查：暂无结果</b></div>`;
const riskItems=(d.risks||[]).map(x=>`<div class="monitorItem warn">${statusIconHtml(false,true,"monitorIcon")}${esc(x)}</div>`).join("")||`<div class="monitorItem ok">${statusIconHtml(true,false,"monitorIcon")}暂无风险提醒。</div>`;
const top=(d.topDomains||[]).map(x=>`<div class="statusItem"><b>${esc(x.domain)}</b><div class="muted">别名 ${x.alias_count||0} · 邮件 ${x.mail_count||0} · 今日 ${x.today_count||0} · 最后 ${x.latest?fmt(x.latest):"暂无"}</div></div>`).join("")||'<div class="statusItem">暂无域名统计。</div>';
const riskCount=(d.risks||[]).length,serviceOk=!!service.ok,healthTitle=serviceOk?`服务运行正常${riskCount?` · ${riskCount} 项提醒`:''}`:"服务状态异常";
setHtml("riskBox",`<details class="domainStatsFold"><summary>${esc(healthTitle)}</summary><div class="domainStatsBody"><div class="monitorBox">${serviceItems}${riskItems}</div><details class="domainStatsFold"><summary>收信配置：${dns.ok?'已接入':'待处理'}</summary><div class="domainStatsBody"><div class="monitorBox">${dnsItems}</div></div></details><details class="domainStatsFold"><summary>按域名统计</summary><div class="domainStatsBody">${top}</div></details></div></details>`);
}
async function loadDomains(){if(!ROOT_PAGE||!byId("domains"))return false;const qs=new URLSearchParams({root:BASE_DOMAIN,page:String(domainPage),pageSize:String(domainPageSize)});const data=await api("/ui-api/domains?"+qs.toString());setText("loginErr","");const canManage=!!data.canManageDomains;setAdminVisible(canManage);setGlobalAdminVisible(!!data.canAddRootDomains);if(!canManage){setHtml("domains","");setHtml("rootTokenList","");setText("dnsTips","");return false}updateAdminScope(data);domainInfoCache={};rememberDomainInfo(data.rootDomainTokens||[]);rememberDomainInfo(data.data||[]);renderRootTabs(data.rootDomains||[]);renderRootTokenPanel(data.rootDomainTokens||[]);domainTotal=data.total||0;domainPage=data.page||domainPage;domainPageSize=data.pageSize||domainPageSize;updateDomainPager();const items=data.data||[];setHtml("domains",items.map(d=>domainCard(d)).join("")||'<div class="empty">这个主域名下暂无域名。</div>');bindDomainActionButtons();$$("[data-save-domain]").forEach(el=>el.addEventListener("click",e=>runButton(e.currentTarget,"正在保存域名设置...",()=>saveDomainSettings(el.dataset.saveDomain),"域名设置已保存")));showDns(DOMAIN,{force:false});await loadOverview().catch(()=>{});return true}
function domainCard(d){
const token=d.token||"";
const kind=d.isRootDomain?"主域名":"子域名";
const deleteAction=!d.isRootDomain?`<button class="danger" data-delete-domain="${esc(d.domain)}">删除子域名</button>`:"";
return `<div class="domain domainCard" data-domain-card="${esc(d.domain)}"><div><div class="email">${esc(d.domain)}</div><div class="meta">${kind} · 所有者：${esc(d.owner||"未填写")} · ${d.aliasCount||0} 个别名 · ${d.mailCount||0} 封邮件 · ${bytes(d.storageBytes)} · 最新 ${d.latest?fmt(d.latest):"暂无"}</div><div class="copyTokenLine">${token?esc(token):"未生成独立 Token"}</div></div><div class="toolbar"><a class="secondary" href="${esc(d.path)}">打开页面</a><button class="secondary" data-copy-link="${esc(d.path)}">复制链接</button>${token?`<button class="secondary" data-copy-token="${esc(token)}">复制 Token</button>`:""}<button class="secondary" data-token-domain="${esc(d.domain)}">${token?"重置 Token":"生成 Token"}</button><button class="secondary" data-check-dns="${esc(d.domain)}">DNS检查</button>${deleteAction}</div><details class="fold domainSettings"><summary>设置</summary><div class="foldBody"><div class="domainForm"><div class="settingsGroup"><div class="settingsGroupTitle">基础信息</div><input data-field="owner" value="${esc(d.owner||"")}" placeholder="所有者"><input data-field="note" value="${esc(d.note||"")}" placeholder="备注"><select data-field="enabled"><option value="1" ${d.enabled?'selected':''}>域名启用</option><option value="0" ${!d.enabled?'selected':''}>域名停用</option></select><select data-field="token_disabled"><option value="0" ${!d.tokenDisabled?'selected':''}>Token 启用</option><option value="1" ${d.tokenDisabled?'selected':''}>Token 禁用</option></select></div><div class="settingsGroup"><div class="settingsGroupTitle">页面展示</div><input data-field="brand_title" value="${esc(d.brandTitle||"")}" placeholder="页面标题"><input data-field="brand_desc" value="${esc(d.brandDesc||"")}" placeholder="页面说明"><input data-field="default_alias" value="${esc(d.defaultAlias||"")}" placeholder="默认别名"><input data-field="theme_color" value="${esc(d.themeColor||"")}" placeholder="主题色 #2563eb"></div><div class="settingsGroup"><div class="settingsGroupTitle">保留与配额</div><input data-field="retention_hours" type="number" value="${d.retentionHours||72}" placeholder="保留小时"><input data-field="cleanup_max_mails" type="number" value="${d.cleanupMaxMails||0}" placeholder="最多保留邮件数"><input data-field="alias_limit" type="number" value="${d.aliasLimit||500000}" placeholder="别名上限"><input data-field="mail_limit" type="number" value="${d.mailLimit||50000}" placeholder="邮件上限"><input data-field="storage_limit_mb" type="number" value="${d.storageLimitMb||1024}" placeholder="容量 MB"></div><div class="settingsGroup"><div class="settingsGroupTitle">Webhook</div><div class="webhookHint">收到新邮件时，把邮件摘要推送到你的外部程序，用于自动通知、自动取码或系统对接。</div><input data-field="webhook_url" value="${esc(d.webhookUrl||"")}" placeholder="Webhook URL"><select data-field="webhook_enabled"><option value="0" ${!d.webhookEnabled?'selected':''}>Webhook 关闭</option><option value="1" ${d.webhookEnabled?'selected':''}>Webhook 开启</option></select></div></div><div class="toolbar" style="margin-top:8px"><button data-save-domain="${esc(d.domain)}">保存设置</button></div></div></details></div>`;
}
async function saveDomainSettings(domain){const card=$(`[data-domain-card="${CSS.escape(domain)}"]`);if(!card)throw new Error("没有找到域名设置");const body={domain};$$("[data-field]",card).forEach(el=>body[el.dataset.field]=el.value);if(body.enabled==="0"){const ok=await dangerFlow([{title:"停用域名",text:`停用后，${esc(domain)} 将不能继续收信或登录。请输入完整域名确认。`,requireText:domain,placeholder:domain,button:"停用域名"}]);if(!ok)return false;body.confirmDomain=domain}await api("/ui-api/domain-settings",{method:"POST",body:JSON.stringify(body)});await loadDomains();return true}
async function resetDomainToken(domain){const info=domainInfoCache[domain]||{},steps=[{title:"重置独立 Token",text:`将为 ${esc(domain)} 生成新的独立 token，旧 token 会失效。`,button:"继续"}];if(info.isRootDomain||domain===rootForDomain(domain)){steps.push({title:"主域名 Token 影响确认",text:`这是主域名 Token。重置后，使用 ${esc(domain)} 主域名后台的人需要改用新 Token。`,requireText:domain,placeholder:domain,button:"重置主域名 Token"})}const ok=await dangerFlow(steps);if(!ok)return false;await api("/ui-api/domain-token",{method:"POST",body:JSON.stringify({domain})});await loadDomains();showDns(domain);return true}
async function deleteManagedDomain(domain){const info=domainInfoCache[domain]||{},isRoot=!!info.isRootDomain||domain===rootForDomain(domain),phrase=isRoot?"删除主域名":"删除子域名";const steps=isRoot?[{title:"删除主域名",text:`将删除 ${esc(domain)} 及其子域名、别名、邮件和附件。系统会先自动备份。请输入完整域名确认。`,requireText:domain,placeholder:domain,button:"下一步"},{title:"最终确认",text:`请输入 <span class="dangerNote">${phrase}</span>。`,requireText:phrase,placeholder:phrase,button:"删除主域名"}]:[{title:"删除子域名",text:`将删除 ${esc(domain)} 的别名、邮件和附件，并先自动备份。请输入完整域名确认。`,requireText:domain,placeholder:domain,button:"删除子域名"}];const ok=await dangerFlow(steps);if(!ok)return false;const shouldClearMailbox=domainMatchesScope(DOMAIN,domain)||domainMatchesScope(currentEmail,domain)||messages.some(m=>domainMatchesScope(m.toEmail,domain)||domainMatchesScope(m.domain,domain));const res=await api("/ui-api/delete-domain",{method:"POST",body:JSON.stringify({domain,confirm:domain,phrase})});const d=res.data||{};if(domain===DOMAIN||domain===BASE_DOMAIN){toast("当前页面域名已删除，将返回 /mail。","ok","删除完成",5000);location.href="/mail";return false}if(shouldClearMailbox)clearMailboxView("已删除该域名，右侧邮件列表已同步清空。");domainPage=1;await loadDomains();await loadAliases().catch(()=>{});return `已删除 ${d.domains||0} 个域名、${d.aliases||0} 个别名、${d.mails||0} 封邮件。`}
function startDnsCountdown(domain,ok){clearInterval(dnsCountdownTimer);const el=byId("dnsCountdown");if(!el||ok){if(el)el.textContent="";return}let left=60;el.textContent=`DNS 未完全生效，建议 ${left} 秒后刷新检查。`;dnsCountdownTimer=setInterval(()=>{left--;if(left<=0){clearInterval(dnsCountdownTimer);el.textContent="可以刷新检查了。";return}el.textContent=`DNS 未完全生效，建议 ${left} 秒后刷新检查。`},1000)}
async function checkDns(domain){const res=await api("/ui-api/dns-check?domain="+encodeURIComponent(domain));const d=res.data,msg=d.ok?`${domain} DNS检查通过`:`${domain} DNS 仍需检查`;setStatusLog(`<b>${esc(domain)} DNS检查</b><div class="statusList">${(d.checks||[]).map(x=>`<div class="statusItem ${statusClass(x.ok)}"><div class="statusTitle">${statusTitle(`${x.name}：${x.ok?'正常':'异常'}`,x.ok)}</div><div>${esc(x.message)}</div></div>`).join("")}</div><div class="toolbar"><button class="secondary" data-recheck-dns="${esc(domain)}">刷新检查</button></div><div class="muted" id="dnsCountdown">如刚修改 Cloudflare，请等待 1-5 分钟后再刷新检查。</div>`);$$("[data-recheck-dns]").forEach(el=>el.addEventListener("click",e=>runButton(e.currentTarget,"正在重新进行DNS检查...",()=>runDnsAction(()=>checkDns(el.dataset.recheckDns)))));startDnsCountdown(domain,d.ok);dnsResultToast(msg,!!d.ok,d.ok?"DNS检查通过":"DNS检查发现异常");return msg}
async function checkHealth(){const res=await api("/ui-api/admin/health"),d=res.data||{},labels={http:"Web",smtp:"SMTP",database:"数据库",disk:"磁盘",backups:"备份"};const items=Object.entries(labels).map(([key,label])=>{const item=(d.components||{})[key]||{},ok=!!item.ok;return `<div class="statusItem ${statusClass(ok,!ok)}"><div class="statusTitle">${statusTitle(`${label}：${ok?'正常':'异常'}`,ok,!ok)}</div><div class="muted">${esc(item.message||'')}</div></div>`}).join("");setHtml("adminOpsLog",`<div class="statusList">${items}</div>`);return d.ok?"健康检查通过":"服务存在异常"}
async function loadBackups(){const res=await api("/ui-api/admin/backups"),sizeOk=Number(res.totalBytes||0)<=Number(res.limitBytes||0);setHtml("adminOpsLog",`<div class="statusItem ${statusClass(sizeOk,!sizeOk)}"><div class="statusTitle">${statusTitle(`备份占用 ${bytes(res.totalBytes)} / ${bytes(res.limitBytes)}`,sizeOk,!sizeOk)}</div></div>`+((res.data||[]).map(b=>`<div class="statusItem"><b>${esc(b.name)}</b><div class="muted">${fmt(b.createdAt)} · ${bytes(b.size)}</div><div class="toolbar"><button class="secondary" data-download-backup="${esc(b.name)}">下载</button><button class="softDanger" data-restore-backup="${esc(b.name)}">恢复</button></div></div>`).join("")||`<div class="statusItem ok"><div class="statusTitle">${statusTitle("暂无备份。",true)}</div></div>`));$$("[data-download-backup]").forEach(b=>b.addEventListener("click",()=>downloadBackup(b.dataset.downloadBackup)));$$("[data-restore-backup]").forEach(b=>b.addEventListener("click",e=>runButton(e.currentTarget,"正在准备恢复流程...",()=>restoreBackup(b.dataset.restoreBackup),msg=>msg)));return "备份列表已刷新"}
async function downloadBackup(name){const res=await fetch("/ui-api/admin/backup-download?name="+encodeURIComponent(name),{headers:headers(false)});if(!res.ok)throw new Error("下载失败");const blob=await res.blob();const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
async function restoreBackup(name){const ok=await dangerFlow([{title:"恢复备份",text:`恢复 ${esc(name)} 会覆盖当前数据库；系统会先保留一份恢复前备份。请输入文件名确认。`,requireText:name,placeholder:name,button:"下一步"},{title:"最终确认",text:`请输入 <span class="dangerNote">恢复备份</span>。`,requireText:"恢复备份",placeholder:"恢复备份",button:"恢复备份"}]);if(!ok)return false;await api("/ui-api/admin/backup-restore",{method:"POST",body:JSON.stringify({name,confirmName:name,confirm:"恢复备份"})});await loadAll();return "备份已恢复"}
async function loadAudit(){const res=await api("/ui-api/admin/audit");setHtml("adminOpsLog",(res.data||[]).map(r=>`<div class="statusItem"><b>${esc(r.action)} · ${esc(r.domain||"")}</b><div class="muted">${fmt(r.created_at)} · ${esc(r.actor||"")}</div><div>${esc(r.detail||"")}</div></div>`).join("")||"暂无审计日志。");return "审计日志已刷新"}
async function exportAudit(){const res=await fetch("/ui-api/admin/audit?format=csv",{headers:headers(false)});if(!res.ok)throw new Error("导出失败");const blob=await res.blob();const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="audit.csv";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);return "审计日志已导出"}
async function loadFailures(){const res=await api("/ui-api/admin/failed-mails");setHtml("adminOpsLog",(res.data||[]).map(r=>`<div class="statusItem bad"><div class="statusTitle">${statusTitle(r.reason||"异常记录",false)}</div><div class="muted">${fmt(r.created_at)} · ${esc(r.rcpt_to||"")}</div><div>${esc(r.detail||"")}</div></div>`).join("")||`<div class="statusItem ok"><div class="statusTitle">${statusTitle("暂无异常记录。",true)}</div></div>`);return "异常记录已刷新"}
async function loadCleanupRuns(){const res=await api("/ui-api/admin/cleanup-runs");setHtml("adminOpsLog",(res.data||[]).map(r=>`<div class="statusItem ok"><div class="statusTitle">${statusTitle(`${r.domain||"全部"} 清理 ${r.deleted_count} 封`,true)}</div><div class="muted">${fmt(r.created_at)} · ${esc(r.reason||"")}</div></div>`).join("")||`<div class="statusItem ok"><div class="statusTitle">${statusTitle("暂无清理记录。",true)}</div></div>`);return "清理记录已刷新"}
async function createBackupNow(){const res=await api("/ui-api/admin/backup-create",{method:"POST",body:"{}"});await loadBackups();return `已创建备份：${bytes(res.data.size)}`}
async function addSubdomain(){const value=val("subdomainInput").trim().toLowerCase();if(!value)throw new Error("请输入子域名");if(value.includes(".")&&value!==BASE_DOMAIN&&!value.endsWith("."+BASE_DOMAIN))throw new Error(`这里添加的是 ${BASE_DOMAIN} 的子域名；新的主域名请用下面入口。`);if(value===BASE_DOMAIN)throw new Error("当前主域名已经存在。");const res=await api("/ui-api/domains",{method:"POST",body:JSON.stringify({domain:value,root:BASE_DOMAIN,owner:val("subdomainOwner")})});setVal("subdomainInput","");setVal("subdomainOwner","");domainPage=1;await loadDomains();showDns(res.data.domain);return `已添加子域名 ${res.data.domain}，Cloudflare 配置已更新。`}
async function addBatchSubdomains(){const raw=val("batchSubdomainInput").trim();if(!raw)throw new Error("请先粘贴要添加的子域名");const issueTokens=val("batchSubdomainToken","0")==="1";const res=await api("/ui-api/domains-bulk",{method:"POST",body:JSON.stringify({root:BASE_DOMAIN,domains:raw,owner:val("batchSubdomainOwner"),issueTokens})});const d=res.data||{};setVal("batchSubdomainInput","");setVal("batchSubdomainOwner","");domainPage=1;await loadDomains();const firstCreated=(d.created||[])[0];if(firstCreated)showDns(firstCreated);const tokenText=(d.tokens||[]).filter(x=>x.token).map(x=>`${x.domain}----${location.origin}${x.path}----${x.token}`).join("\n");if(tokenText)await copyText(tokenText,"批量子域名 Token 已复制");return `已新增 ${d.created?.length||0} 个，已存在 ${d.existing?.length||0} 个，失败 ${d.errors?.length||0} 个。`}
async function addRootDomain(){const value=val("rootDomainInput").trim().toLowerCase();if(!value)throw new Error("请输入新的主域名");if(!value.includes("."))throw new Error("新的主域名需要填写完整域名，例如 example.com。");if(value.endsWith("."+BASE_DOMAIN))throw new Error(`这是 ${BASE_DOMAIN} 的子域名，请用上面的子域名入口。`);const res=await api("/ui-api/domains",{method:"POST",body:JSON.stringify({domain:value,root:value,owner:val("rootDomainOwner")})});setVal("rootDomainInput","");setVal("rootDomainOwner","");domainPage=1;await loadDomains();showDns(res.data.domain);return `已添加主域名 ${res.data.domain}，Cloudflare 配置已更新。`}
async function loadAll(){if(ROOT_PAGE){try{await loadDomains()}catch(e){setAdminVisible(false);setGlobalAdminVisible(false);setText("loginErr",errText(e))}}await loadAliases();await restoreRememberedMailbox();document.body.classList.add("isAuthed");setText("loginErr","");setLiveState("connected","实时同步")}
function resetPanel(){aliases=[];messages=[];messageIds=[];selectedIds.clear();aliasTotal=0;aliasPage=1;mailTotal=0;mailPage=1;lastLatest=0;lastDomainLatest=0;aliasesSignature="";currentEmail="";currentMessageId="";domainInfoCache={};storeRemove(CURRENT_KEY);document.body.classList.remove("isAuthed");setAdminDrawer(false);renderAliases();renderMessages();setText("currentTitle","请选择别名");setText("currentMeta","选择别名查看邮件");setHtml("mailList",'<div class="empty">选择左侧别名开始收件。</div>');setHtml("mailDetail",'<div class="empty">选择一封邮件查看内容。</div>');setAdminVisible(false);setGlobalAdminVisible(false);setHtml("domains","");setHtml("rootTokenList","");setHtml("dnsBulkLog","");setLiveState("idle","未登录")}
function notifyNewMail(item,count){const now=Date.now();if(now-lastLiveToastAt>2500){toast(`收到 ${count} 封新邮件，已自动打开最新一封。`,"ok","新邮件");lastLiveToastAt=now}if(storeGet("ferret_mail_notify")==="1"&&window.Notification&&Notification.permission==="granted"){new Notification("收到新邮件",{body:`${item.fromEmail||""} ${item.code?("验证码 "+item.code):""}`})}if(storeGet("ferret_mail_notify")==="1"){try{const ctx=new (window.AudioContext||window.webkitAudioContext)();const osc=ctx.createOscillator();const gain=ctx.createGain();osc.frequency.value=880;gain.gain.value=.04;osc.connect(gain);gain.connect(ctx.destination);osc.start();setTimeout(()=>{osc.stop();ctx.close()},180)}catch(e){}}}
async function toggleNotify(){if(storeGet("ferret_mail_notify")==="1"){storeSet("ferret_mail_notify","0");setText("notifyToggle","通知");toast("已关闭浏览器通知和提示音。","ok","通知");return}if(window.Notification&&Notification.permission!=="granted"){await Notification.requestPermission()}storeSet("ferret_mail_notify","1");setText("notifyToggle","通知开");toast("已开启浏览器通知和提示音。","ok","通知")}
async function liveChangeLoop(){if(liveLoopStarted)return;liveLoopStarted=true;while(true){try{if(token&&!document.hidden){if(aliasesLoading||messagesLoading){await new Promise(r=>setTimeout(r,500));continue}setLiveState("connected","实时同步");const aliasMode=val("mailScope","alias")==="alias",watchEmail=aliasMode&&currentEmail?currentEmail:"",since=watchEmail?lastLatest:lastDomainLatest;const qs=new URLSearchParams({domain:DOMAIN,since:String(since||0)});if(watchEmail)qs.set("email",watchEmail);const res=await api("/ui-api/changes?"+qs.toString());const d=res.data||{};setLiveState("connected","实时同步");if(d.latest)lastDomainLatest=Math.max(lastDomainLatest,Number(d.latest||0));if(watchEmail&&d.latest)lastLatest=Math.max(lastLatest,Number(d.latest||0));if(d.changed){if(watchEmail){await loadMessages("",{preserve:true,auto:true,keepPage:true});await loadAliases("",{auto:true})}else if(val("mailScope","alias")==="domain"){await loadMessages("",{preserve:true,auto:true,keepPage:true});await loadAliases("",{auto:true})}else{await loadAliases("",{auto:true});const target=d.latestEmail||(latestAliasItem()||{}).email;if(target)await loadMessages(target,{auto:true})}}}else{if(!token)setLiveState("idle","未登录");await new Promise(r=>setTimeout(r,1200))}}catch(e){setLiveState(navigator.onLine?"error":"offline",navigator.onLine?"同步中断":"网络已断开");const now=Date.now();if(now-lastLiveErrorAt>15000){toast(errText(e),"err","自动同步失败");lastLiveErrorAt=now}await new Promise(r=>setTimeout(r,2500))}}}
const ruleSelect=byId("ruleSelect");if(ruleSelect)ruleSelect.innerHTML=rules.map(r=>`<option value="${r.id}">${r.name}</option>`).join("");
["ruleSelect","batchBase","batchStart","batchCount","customTemplate"].forEach(id=>on(id,"input",renderGenerator));
["mailSearch","mailCodeSearch","mailDateFrom","mailDateTo"].forEach(id=>on(id,"input",()=>{clearTimeout(mailTimer);mailTimer=setTimeout(()=>{mailPage=1;loadMessages("",{preserve:true}).catch(e=>toast(errText(e),"err","搜索失败"))},280)}));
["filterCode","filterLink","filterUnread","filterToday","filterStarred","filterPinned"].forEach(id=>on(id,"change",()=>{mailPage=1;loadMessages("",{preserve:true}).catch(e=>toast(errText(e),"err","筛选失败"))}));
on("themeToggle","click",()=>setTheme(document.documentElement.dataset.theme==="dark"?"light":"dark"));
on("visualTheme","change",e=>{setVisual(e.currentTarget.value);setTheme("light",true)});
on("notifyToggle","click",toggleNotify);setText("notifyToggle",storeGet("ferret_mail_notify")==="1"?"通知开":"通知");
on("aliasInput","input",()=>setText("aliasPreview",aliasValue()||"输入前缀即可创建"));
on("aliasPageSize","change",e=>runButton(e.currentTarget,"正在切换分页...",async()=>{aliasPageSize=Number(val("aliasPageSize","50")||50);aliasPage=1;await loadAliases()},"分页已更新"));
on("aliasSearch","input",()=>{clearTimeout(aliasTimer);aliasTimer=setTimeout(()=>{aliasQuery=val("aliasSearch").trim();aliasPage=1;loadAliases().catch(e=>{setText("loginErr",errText(e));toast(errText(e),"err","搜索失败")})},250)});
on("aliasPrev","click",e=>runButton(e.currentTarget,"正在加载上一页...",async()=>{if(aliasPage<=1)return false;aliasPage--;await loadAliases()},"已加载上一页"));
on("aliasNext","click",e=>runButton(e.currentTarget,"正在加载下一页...",async()=>{if(aliasPage>=Math.ceil(aliasTotal/aliasPageSize))return false;aliasPage++;await loadAliases()},"已加载下一页"));
on("mailPageSize","change",e=>runButton(e.currentTarget,"正在切换邮件分页...",async()=>{mailPageSize=Number(val("mailPageSize","50")||50);mailPage=1;await loadMessages("",{preserve:true})},"邮件分页已更新"));
on("mailScope","change",e=>runButton(e.currentTarget,"正在切换搜索范围...",async()=>{mailPage=1;await loadMessages("",{preserve:true})},"搜索范围已更新"));
on("mailPrev","click",e=>runButton(e.currentTarget,"正在加载上一页邮件...",async()=>{if(mailPage<=1)return false;mailPage--;await loadMessages("",{preserve:true,keepPage:true})},"已加载上一页"));
on("mailNext","click",e=>runButton(e.currentTarget,"正在加载下一页邮件...",async()=>{if(mailPage>=Math.ceil(mailTotal/mailPageSize))return false;mailPage++;await loadMessages("",{preserve:true,keepPage:true})},"已加载下一页"));
on("selectAllMail","click",()=>{messages.forEach(m=>selectedIds.add(String(m.id)));renderMessages();toast("已选择本页邮件。","ok","批量选择")});
on("bulkRead","click",e=>runButton(e.currentTarget,"正在批量标记已读...",()=>bulkMail("read"),msg=>msg));
on("bulkUnread","click",e=>runButton(e.currentTarget,"正在批量标记未读...",()=>bulkMail("unread"),msg=>msg));
on("bulkDelete","click",e=>runButton(e.currentTarget,"正在批量删除...",()=>bulkMail("delete"),msg=>msg));
on("bulkCopyCodes","click",e=>runButton(e.currentTarget,"正在复制验证码...",copySelectedCodes,"验证码已复制"));
on("clearAliasMail","click",e=>runButton(e.currentTarget,"正在清空当前别名邮件...",()=>clearAliasMessages(),msg=>msg));
async function enterWithToken(){const candidate=val("token").trim();if(!candidate)throw new Error("请输入访问 Token");token=candidate;try{await loadAll();storeSet(TOKEN_KEY,token);storeRemove("ferret_mail_token")}catch(e){token="";storeRemove(TOKEN_KEY);document.body.classList.remove("isAuthed");setLiveState("idle","登录失败");throw e}}
on("tokenForm","submit",e=>{e.preventDefault();runButton(byId("saveToken"),"正在验证访问密钥...",enterWithToken,"已进入，数据已刷新")});
on("clearToken","click",()=>{storeRemove(TOKEN_KEY);storeRemove("ferret_mail_token");token="";setVal("token","");resetPanel();hideDnsGuide();showDns(DOMAIN,{force:false});toast("已退出，页面数据已清空。","ok","已退出")});
on("refreshAll","click",e=>runButton(e.currentTarget,"正在刷新别名和邮件...",async()=>{await loadAll();if(currentEmail||val("mailScope")==="domain")await loadMessages("",{preserve:true})},"已刷新别名和邮件"));
on("refreshMessages","click",e=>runButton(e.currentTarget,"正在刷新邮件...",()=>loadMessages("",{preserve:true}),"已刷新邮件"));
on("copyAddress","click",()=>copyText(currentEmail,"邮箱地址已复制"));
on("clearDomainMail","click",e=>runButton(e.currentTarget,"正在处理清空邮件...",()=>clearDomainMessages(),msg=>msg));
on("clearAliases","click",e=>runButton(e.currentTarget,"正在处理清空别名...",()=>clearAllAliases(),msg=>msg));
on("hideCloudflareGuide","click",hideDnsGuide);
on("exportAliasLinks","click",e=>runButton(e.currentTarget,"正在导出全部别名接码链接...",exportAliasShareLinks,msg=>msg));
on("addAlias","click",e=>runButton(e.currentTarget,"正在添加别名...",async()=>{const email=aliasValue();if(!email)throw new Error("请先输入要添加的别名前缀");await api("/ui-api/aliases",{method:"POST",body:JSON.stringify({email,domain:DOMAIN})});setVal("aliasInput","");setText("aliasPreview","输入前缀即可创建");aliasPage=1;await loadAliases(email);return `已添加 ${email}`},msg=>msg));
on("addBatch","click",e=>runButton(e.currentTarget,"正在批量添加别名...",async()=>{const aliasesToAdd=generatedAliases();if(!aliasesToAdd.length)throw new Error("没有可添加的别名");const res=await api("/ui-api/bulk-aliases",{method:"POST",body:JSON.stringify({domain:DOMAIN,aliases:aliasesToAdd})});aliasPage=1;await loadAliases();return `已新增 ${res.data.created} 个，已存在 ${res.data.existing} 个。`},msg=>msg));
on("addSubdomain","click",e=>runButton(e.currentTarget,"正在添加子域名...",addSubdomain,msg=>msg));
on("addBatchSubdomains","click",e=>runButton(e.currentTarget,"正在批量添加子域名...",addBatchSubdomains,msg=>msg));
on("addRootDomain","click",e=>runButton(e.currentTarget,"正在添加主域名...",addRootDomain,msg=>msg));
on("openAdminDrawer","click",()=>{setAdminView(storeGet("ferret_admin_view","overview"));setAdminDrawer(true)});
on("closeAdminDrawer","click",()=>setAdminDrawer(false));
on("adminDrawerBackdrop","click",()=>setAdminDrawer(false));
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&!byId("adminDrawer")?.classList.contains("drawerClosed"))setAdminDrawer(false)});
$$("[data-admin-view]").forEach(el=>el.addEventListener("click",()=>setAdminView(el.dataset.adminView)));
on("exportRootTokens","click",e=>runButton(e.currentTarget,"正在导出主域名 Token...",()=>downloadDomainExport("root-tokens"),msg=>msg));
on("exportAllDns","click",e=>runButton(e.currentTarget,"正在导出全部Cloudflare配置...",()=>downloadDomainExport("dns-all"),msg=>msg));
on("exportCurrentDns","click",e=>runButton(e.currentTarget,"正在导出当前Cloudflare配置...",()=>downloadDomainExport("dns-current"),msg=>msg));
on("exportCurrentTokens","click",e=>runButton(e.currentTarget,"正在导出当前主域名 Token...",()=>downloadDomainExport("current-tokens"),msg=>msg));
on("checkAllDns","click",e=>runButton(e.currentTarget,"正在进行全部域名DNS检查...",()=>runDnsAction(()=>checkDnsBulk("all"))));
on("checkEveryDns","click",e=>runButton(e.currentTarget,"正在进行全部域名DNS检查...",()=>runDnsAction(()=>checkDnsBulk("all"))));
on("checkCurrentRootDns","click",e=>runButton(e.currentTarget,"正在进行当前主域名DNS检查...",()=>runDnsAction(()=>checkDnsBulk("current"))));
on("checkCurrentRootDnsInline","click",e=>runButton(e.currentTarget,"正在进行当前主域名DNS检查...",()=>runDnsAction(()=>checkDnsBulk("current"))));
on("domainPrev","click",e=>runButton(e.currentTarget,"正在加载上一页域名...",async()=>{if(domainPage<=1)return false;domainPage--;await loadDomains()},"已加载上一页"));
on("domainNext","click",e=>runButton(e.currentTarget,"正在加载下一页域名...",async()=>{if(domainPage>=Math.ceil(domainTotal/domainPageSize))return false;domainPage++;await loadDomains()},"已加载下一页"));
on("checkHealth","click",e=>runButton(e.currentTarget,"正在健康检查...",checkHealth,msg=>msg));
on("createBackup","click",e=>runButton(e.currentTarget,"正在创建备份...",createBackupNow,msg=>msg));
on("loadBackups","click",e=>runButton(e.currentTarget,"正在加载备份列表...",loadBackups,msg=>msg));
on("loadAudit","click",e=>runButton(e.currentTarget,"正在加载审计日志...",loadAudit,msg=>msg));
on("exportAudit","click",e=>runButton(e.currentTarget,"正在导出审计日志...",exportAudit,msg=>msg));
on("loadFailures","click",e=>runButton(e.currentTarget,"正在加载异常记录...",loadFailures,msg=>msg));
on("loadCleanupRuns","click",e=>runButton(e.currentTarget,"正在加载清理记录...",loadCleanupRuns,msg=>msg));
document.addEventListener("visibilitychange",()=>{if(!document.hidden&&token){loadAliases("",{auto:true}).then(()=>{if(currentEmail||val("mailScope")==="domain")return loadMessages("",{preserve:true,auto:true});const latest=latestAliasItem();if(latest&&latest.email)return loadMessages(latest.email,{auto:true});return false}).catch(()=>{})}});
window.addEventListener("online",()=>setLiveState(token?"syncing":"idle",token?"正在重连":"未登录"));
window.addEventListener("offline",()=>setLiveState("offline","网络已断开"));
window.addEventListener("error",e=>toast(e.message||"页面脚本错误","err","页面错误"));
window.addEventListener("unhandledrejection",e=>toast(errText(e.reason),"err","页面错误"));
renderGenerator();renderMessages();showDns(DOMAIN,{force:false});
if(token)loadAll().catch(e=>{token="";storeRemove(TOKEN_KEY);setText("loginErr",errText(e));setLiveState("idle","登录失败");toast(errText(e),"err","加载失败")}).finally(liveChangeLoop);else{setLiveState("idle","未登录");liveChangeLoop()}
</script>
</body>
</html>'''

ALIAS_CODE_HTML = r'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="alternate icon" href="/favicon.ico" type="image/png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta name="theme-color" content="#1769aa">
<title>别名接码</title>
<style>
:root{color-scheme:light;--bg:#f5f6f8;--panel:#fff;--panel2:#f0f2f5;--text:#15171a;--muted:#6b7280;--border:#d9dee7;--accent:#2563eb;--accentText:#fff;--danger:#dc2626;--ok:#0f766e;--shadow:0 10px 28px rgba(15,23,42,.08)}
[data-theme=light][data-palette=mint]{--bg:#eef8f4;--panel:#fff;--panel2:#e6f3ed;--text:#17332a;--muted:#587268;--border:#cfe2da;--accent:#168463;--ok:#15734f}
[data-theme=light][data-palette=rose]{--bg:#fff3f6;--panel:#fff;--panel2:#fae9ef;--text:#3b202b;--muted:#80616e;--border:#ecd2dc;--accent:#b94f75;--ok:#34765f}
[data-theme=light][data-palette=sand]{--bg:#faf5eb;--panel:#fffefa;--panel2:#f3eadc;--text:#3b2d1f;--muted:#7a6855;--border:#e5d7c4;--accent:#966329;--ok:#42745b}
[data-theme=dark]{color-scheme:dark;--bg:#17191d;--panel:#1d2025;--panel2:#23272e;--text:#edf1f7;--muted:#a3aab5;--border:#3a404a;--accent:#77a6ff;--accentText:#0d1728;--danger:#ff8a8a;--ok:#5dd2bd;--shadow:none}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,sans-serif}button,input,select{font:inherit}button{min-height:36px;border:1px solid var(--accent);background:var(--accent);color:var(--accentText);border-radius:7px;padding:0 12px;cursor:pointer}button.secondary{background:var(--panel);color:var(--text);border-color:var(--border)}button:disabled{opacity:.55;cursor:not-allowed}input,select{height:38px;border:1px solid var(--border);background:var(--panel);color:var(--text);border-radius:7px;padding:0 10px;min-width:0}.shell{width:min(1180px,100%);margin:0 auto;padding:16px}.top{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:12px}.brand{font-size:22px;font-weight:800;word-break:break-all}.muted{color:var(--muted);font-size:13px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.card,.list,.detail{background:var(--panel);border:1px solid var(--border);border-radius:8px;box-shadow:var(--shadow)}.card{padding:12px;margin-bottom:12px}.grid{display:grid;grid-template-columns:minmax(280px,410px) minmax(0,1fr);gap:12px;min-height:calc(100vh - 158px)}.list,.detail{min-height:0;overflow:auto}.mail{padding:12px;border-bottom:1px solid var(--border);cursor:pointer}.mail:hover,.mail.active{background:var(--panel2)}.subject{font-weight:750;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.preview{font-size:13px;color:var(--muted);margin-top:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.code{display:inline-flex;background:var(--ok);color:#062016;border-radius:6px;padding:2px 7px;font-weight:850;margin-left:6px}.codeQuickBtn{min-height:auto;border:0;cursor:pointer;line-height:1.3;vertical-align:baseline}.codeQuickBtn:hover{filter:brightness(1.08)}.codeQuickBtn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.detail{padding:15px}.detail h1{font-size:20px;margin:0 0 9px;line-height:1.3}.plain{white-space:pre-wrap;line-height:1.58;border:1px solid var(--border);background:var(--panel2);border-radius:8px;padding:12px;overflow:auto;max-height:62vh}.actions{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.actions a{background:var(--accent);color:var(--accentText);text-decoration:none;border-radius:7px;padding:9px 12px;font-weight:650}.empty{padding:14px;color:var(--muted);font-size:13px}.err{color:var(--danger);font-weight:700}.toast{position:fixed;right:16px;bottom:16px;max-width:min(360px,calc(100vw - 32px));background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:11px 13px;box-shadow:var(--shadow);font-size:13px;display:none}.toast.show{display:block}@media(max-width:820px){.shell{padding:12px}.top{display:block}.top .toolbar{margin-top:10px}.grid{grid-template-columns:1fr;min-height:0}.list{max-height:48vh}.detail{min-height:46vh}.toolbar button,.toolbar input,.toolbar select{flex:1}.brand{font-size:19px}.detail h1{font-size:18px}}
</style>
</head>
<body>
<div class="shell">
  <header class="top">
    <div>
      <div class="brand" id="aliasTitle">验证码收件箱</div>
      <div class="muted" id="aliasMeta">正在验证链接...</div>
    </div>
    <div class="toolbar"><select id="paletteSelect" aria-label="选择浅色主题"><option value="sky">天光</option><option value="mint">薄荷</option><option value="rose">蔷薇</option><option value="sand">暖砂</option></select><button class="secondary" id="themeBtn">深色</button><button id="refreshBtn">刷新</button><button class="secondary" id="copyCodesBtn">复制本页验证码</button></div>
  </header>
  <section class="card">
    <div class="toolbar"><input id="searchInput" placeholder="搜索邮件或验证码"><button class="secondary" id="clearSearchBtn">清空</button></div>
  </section>
  <main class="grid">
    <section class="list" id="mailList"><div class="empty">正在加载...</div></section>
    <section class="detail" id="mailDetail"><div class="empty">选择一封邮件查看内容。</div></section>
  </main>
</div>
<div class="toast" id="toast"></div>
<script>
const token=(location.pathname.split("/").pop()||"").trim();
const $=(s,root=document)=>root.querySelector(s),$$=(s,root=document)=>Array.from(root.querySelectorAll(s));
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt=ts=>ts?new Date(Number(ts)).toLocaleString():"";
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let mails=[],currentId="",latest=0,total=0,page=1,pageSize=100,loading=false,lastErrorAt=0;
function setText(id,v){const el=document.getElementById(id);if(el)el.textContent=v}
function html(id,v){const el=document.getElementById(id);if(el)el.innerHTML=v}
function toast(msg){const el=$("#toast");el.textContent=msg;el.classList.add("show");clearTimeout(el._t);el._t=setTimeout(()=>el.classList.remove("show"),2800)}
const aliasPalettes=new Set(["sky","mint","rose","sand"]);
function theme(v){document.documentElement.dataset.theme=v;localStorage.setItem("alias_code_theme",v);setText("themeBtn",v==="dark"?"浅色":"深色")}
function palette(v){const next=aliasPalettes.has(v)?v:"sky";document.documentElement.dataset.palette=next;localStorage.setItem("alias_code_palette",next);const select=$("#paletteSelect");if(select)select.value=next}
palette(localStorage.getItem("alias_code_palette")||"sky");
theme(localStorage.getItem("alias_code_theme")||((matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light"));
async function req(path,params={}){params.token=token;const qs=new URLSearchParams(params),controller=new AbortController(),timer=setTimeout(()=>controller.abort(),path.includes("/changes")?35000:15000);try{const res=await fetch(path+"?"+qs.toString(),{headers:{accept:"application/json"},cache:"no-store",signal:controller.signal});const data=await res.json().catch(()=>({}));if(!res.ok||data.code>=400)throw new Error(data.message||"链接无效或已被禁用");return data}finally{clearTimeout(timer)}}
function renderList(){
if(!mails.length){html("mailList",'<div class="empty">当前没有邮件。</div>');return}
const more=total>mails.length?'<div class="empty"><button class="secondary" id="loadMoreBtn">加载更多</button></div>':'';
html("mailList",mails.map(m=>{const codeBtn=m.code?`<button type="button" class="code codeQuickBtn" data-copy-code="${esc(m.code)}" title="点击复制验证码" aria-label="点击复制验证码 ${esc(m.code)}">复制 ${esc(m.code)}</button>`:"";return `<div class="mail ${String(m.id)===String(currentId)?'active':''}" data-id="${m.id}"><div class="subject">${esc(m.subject||'(无标题)')} ${codeBtn}</div><div class="preview">${esc(m.fromEmail||'')} · ${fmt(m.receivedAt)}</div><div class="preview">${esc((m.text||m.content||'').slice(0,140))}</div></div>`}).join("")+more);
$$("button[data-copy-code]").forEach(el=>el.addEventListener("click",e=>{e.stopPropagation();copy(el.dataset.copyCode,"验证码已复制")}));
$$(".mail").forEach(el=>el.addEventListener("click",e=>{if(e.target.closest("button,a,input"))return;openMail(el.dataset.id)}));
const moreBtn=$("#loadMoreBtn");if(moreBtn)moreBtn.onclick=()=>{page++;load(true,true)}
}
async function load(preserve=false,append=false){if(loading)return;loading=true;try{if(!append)page=1;const data=await req("/public-api/alias-share",{page,pageSize,q:$("#searchInput").value.trim()});const d=data.data||{};const incoming=d.messages||[];if(append){const seen=new Set(mails.map(m=>String(m.id)));mails=mails.concat(incoming.filter(m=>!seen.has(String(m.id))))}else mails=incoming;total=d.total||0;latest=Math.max(Number(d.latest||0),...mails.map(m=>Number(m.receivedAt||0)),latest||0);setText("aliasTitle",d.email||"验证码收件箱");setText("aliasMeta",`${total>mails.length?mails.length+" / ":""}${total} 封 · 自动刷新`);renderList();if(mails.length&&(!preserve||!currentId))await openMail(mails[0].id);if(!mails.length)html("mailDetail",'<div class="empty">当前没有邮件可显示。</div>')}catch(e){if(append)page=Math.max(1,page-1);setText("aliasMeta","链接不可用");html("mailList",`<div class="empty err">${esc(e.message)}</div>`);html("mailDetail",'<div class="empty">请联系链接提供者重新生成接码链接。</div>')}finally{loading=false}}
async function openMail(id){currentId=String(id);renderList();html("mailDetail",'<div class="empty">正在打开邮件...</div>');try{const res=await req("/public-api/alias-share/message",{id});const m=res.data||{};const links=(m.links||[]).map(x=>`<a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.label||'打开链接')}</a>`).join("");html("mailDetail",`<h1>${esc(m.subject||'(无标题)')} ${m.code?`<span class="code">${esc(m.code)}</span>`:''}</h1><div class="muted">From: ${esc(m.fromEmail||'')}<br>To: ${esc(m.toEmail||'')}<br>${fmt(m.receivedAt)}</div><div class="toolbar" style="margin-top:12px">${m.code?'<button class="secondary" id="copyCode">复制验证码</button>':''}<button class="secondary" id="copyText">复制全文</button></div>${links?`<div class="actions">${links}</div>`:''}<div class="plain">${esc(m.text||m.content||'')}</div>`);const cc=$("#copyCode");if(cc)cc.onclick=()=>copy(m.code,"验证码已复制");$("#copyText").onclick=()=>copy(m.text||m.content||"","全文已复制")}catch(e){html("mailDetail",`<div class="empty err">${esc(e.message)}</div>`)}}
function fallbackCopy(value){const ta=document.createElement("textarea");ta.value=String(value||"");ta.setAttribute("readonly","");ta.style.position="fixed";ta.style.left="-9999px";ta.style.top="0";ta.style.opacity="0";document.body.appendChild(ta);ta.focus();ta.select();ta.setSelectionRange(0,ta.value.length);let ok=false;try{ok=document.execCommand&&document.execCommand("copy")}catch(e){ok=false}ta.remove();return !!ok}
async function copy(value,msg){if(!value){toast("没有可复制内容");return}try{if(navigator.clipboard&&navigator.clipboard.writeText){await navigator.clipboard.writeText(value);toast(msg||"已复制");return}}catch(e){}if(fallbackCopy(value)){toast(msg||"已复制");return}toast("复制失败，请手动选择内容。")}
async function copyCodes(){const lines=mails.filter(m=>m.code).map(m=>`${m.code}    ${m.subject||""}`);if(!lines.length){toast("本页没有识别到验证码");return}await copy(lines.join("\n"),"本页验证码已复制")}
async function liveLoop(){while(true){try{if(!document.hidden){const res=await req("/public-api/alias-share/changes",{since:latest});if(res.data&&res.data.changed){toast("收到新邮件，已自动刷新");await load(true)}}await sleep(1200)}catch(e){const now=Date.now();if(now-lastErrorAt>15000){toast(e.message);lastErrorAt=now}await sleep(4000)}}}
$("#themeBtn").onclick=()=>theme(document.documentElement.dataset.theme==="dark"?"light":"dark");
$("#paletteSelect").onchange=e=>{palette(e.currentTarget.value);theme("light")};
$("#refreshBtn").onclick=()=>load(true).then(()=>toast("已刷新"));
$("#copyCodesBtn").onclick=copyCodes;
$("#clearSearchBtn").onclick=()=>{$("#searchInput").value="";page=1;load(false)};
let timer=0;$("#searchInput").oninput=()=>{clearTimeout(timer);timer=setTimeout(()=>load(false),280)};
if(!token)html("mailList",'<div class="empty err">链接缺少 token。</div>');else{load(false);liveLoop()}
</script>
</body>
</html>'''

def domain_path(domain):
    if domain == DOMAIN:
        return "/mail"
    root = root_domain_for(domain) or DOMAIN
    suffix = "." + root
    if root == DOMAIN and domain.endswith(suffix):
        return "/mail/" + domain[:-len(suffix)]
    return "/mail/" + domain


def mail_html(domain=DOMAIN):
    domain = normalize_domain(domain)
    root_domain = root_domain_for(domain) or DOMAIN
    cfg = domain_config(domain)
    brand_title = (cfg.get("brand_title") or domain).strip()
    brand_desc = (cfg.get("brand_desc") or "域名收件箱").strip()
    default_alias = (cfg.get("default_alias") or "a").strip() or "a"
    if not re.match(r"^[a-z0-9._+-]{1,64}$", default_alias, re.I):
        default_alias = "a"
    theme_color = (cfg.get("theme_color") or "").strip()
    tenant_style = f"html:not([data-theme=dark]){{--accent:{theme_color};--accent2:{theme_color};}}" if re.match(r"^#[0-9a-f]{6}$", theme_color, re.I) else ""
    admin_block = ""
    admin_ops_block = ""
    if domain == root_domain:
        admin_block = """
    <div class="box hidden adminOnly adminLauncher" id="adminNavBox">
      <button type="button" id="openAdminDrawer">打开管理工作台</button>
      <div class="muted" id="adminScopeLine">正在加载权限</div>
    </div>
    <div class="adminDrawer hidden adminOnly drawerClosed" id="adminDrawer" aria-hidden="true">
      <button type="button" class="adminDrawerBackdrop" id="adminDrawerBackdrop" aria-label="关闭管理工作台"></button>
      <section class="adminSheet" role="dialog" aria-modal="true" aria-labelledby="adminDrawerTitle">
      <div class="adminDrawerHeader"><div><div class="adminDrawerTitle" id="adminDrawerTitle">管理工作台</div><div class="muted">__BASE_DOMAIN__</div></div><button type="button" class="secondary" id="closeAdminDrawer">关闭</button></div>
      <div class="adminNav" aria-label="管理功能">
        <button class="secondary" data-admin-view="overview">运行总览</button>
        <button class="secondary" data-admin-view="domains">域名管理和接入</button>
        <button class="secondary globalAdminOnly" data-admin-view="roots">多主域名</button>
        <button class="secondary" data-admin-view="dns">DNS检查</button>
        <button class="secondary globalAdminOnly" data-admin-view="ops">系统运维</button>
      </div>
    <div class="box hidden adminOnly cloudflareGuideBox guideHiddenByStatus guideBodyCollapsed" id="cloudflareGuideBox">
      <div class="cloudflareGuideSummary"><span>Cloudflare 配置方式</span><span class="toolbar cloudflareGuideHeaderActions"><button type="button" class="secondary" data-guide-body-toggle="1">收起正文</button><button type="button" class="secondary" id="hideCloudflareGuide" data-guide-hide="1" onclick="event.preventDefault();event.stopPropagation();window.__ferretGuideHidden=true;document.getElementById('cloudflareGuideBox').classList.add('guideHiddenByStatus','guideBodyCollapsed');document.querySelectorAll('[data-access-action=guide]').forEach(b=>b.textContent='查看Cloudflare配置')">隐藏配置</button></span></div>
      <div class="cloudflareGuideBody">
        <div class="cloudflareGuideDomain" id="cloudflareGuideDomain">当前配置域名：__DOMAIN__</div>
        <div class="cloudflareGuideHelp">这里统一显示当前页面或刚点击 DNS检查 的域名配置。进入 Cloudflare 后台的 DNS 记录页后，按下面内容添加 MX 和 A 记录；A 记录必须保持 DNS only / 灰云。</div>
        <div class="dns cloudflareGuide" id="dnsTips"></div>
      </div>
    </div>
    <div class="box hidden adminOnly adminPanelSection" data-admin-section="overview" id="overviewBox">
      <div class="sectionTitle">运行总览</div>
      <div class="tabs" id="rootTabs"></div>
      <div class="accessStatus" id="adminAccessStatus"></div>
      <div class="statsGrid" id="overviewStats"></div>
      <div class="logBox" id="riskBox" style="margin-top:8px"></div>
    </div>
    <div class="box hidden adminOnly globalAdminOnly adminPanelSection" data-admin-section="roots" id="rootTokenBox">
      <div class="sectionTitle">多主域名</div>
      <div class="domainAddHelp">每个主域名都有独立页面和 Token；这里展示入口、统计、DNS检查和导出操作。</div>
      <div class="toolbar" style="margin:8px 0"><button class="secondary" id="exportRootTokens">导出主域名 Token</button><button class="secondary" id="checkAllDns">全部域名DNS检查</button><button class="secondary" id="exportAllDns">导出全部Cloudflare配置</button></div>
      <div class="rootTokenList" id="rootTokenList"></div>
    </div>
    <div class="box hidden adminOnly adminPanelSection" data-admin-section="domains" id="domainBox">
      <div class="sectionTitle">域名管理和接入</div>
      <details class="domainStatsFold" id="domainAccessFold">
        <summary>新增域名和接入配置</summary>
        <div class="domainStatsBody">
          <div class="domainAddGrid">
            <div class="domainAddGroup">
              <div class="domainAddTitle">添加当前主域名的子域名</div>
              <div class="domainAddHelp">例如输入 wenxin，会添加 wenxin.__BASE_DOMAIN__。</div>
              <div class="row"><input id="subdomainInput" placeholder="例如 wenxin"><input id="subdomainOwner" placeholder="所有者名称"><button id="addSubdomain">添加子域名</button></div>
            </div>
            <div class="domainAddGroup">
              <div class="domainAddTitle">批量添加子域名</div>
              <div class="domainAddHelp">每行一个，例如 api、team、code；也可以粘贴完整子域名。不会允许添加到其他主域名下面。</div>
              <textarea class="batchArea" id="batchSubdomainInput" placeholder="api&#10;team&#10;code"></textarea>
              <div class="row"><input id="batchSubdomainOwner" placeholder="统一所有者名称"><select id="batchSubdomainToken"><option value="0">不生成 Token</option><option value="1">同时生成 Token</option></select><button id="addBatchSubdomains">批量添加子域名</button></div>
            </div>
            <div class="domainAddGroup hidden globalAdminOnly">
              <div class="domainAddTitle">添加新的主域名</div>
              <div class="domainAddHelp">例如 example.com，会生成独立页面 /mail/example.com。</div>
              <div class="row"><input id="rootDomainInput" placeholder="例如 example.com"><input id="rootDomainOwner" placeholder="所有者名称"><button id="addRootDomain">添加主域名</button></div>
            </div>
          </div>
        </div>
      </details>
      <div class="toolbar" style="margin-top:8px"><button class="secondary" id="exportCurrentTokens">导出当前主域名 Token</button><button class="secondary" id="checkCurrentRootDnsInline">当前主域名DNS检查</button></div>
      <div class="pager" style="margin-top:8px"><button class="secondary" id="domainPrev">上一页</button><div class="muted" id="domainPageInfo">0 个域名</div><button class="secondary" id="domainNext">下一页</button></div>
      <div class="logBox" id="domainOpsLog" style="margin-top:8px"></div>
      <div class="domains" id="domains" style="margin-top:10px"></div>
    </div>
    <div class="box hidden adminOnly adminPanelSection" data-admin-section="dns" id="dnsBulkBox">
      <div class="sectionTitle">DNS检查</div>
      <div class="domainAddHelp">可以检测当前主域名下所有域名；全局管理员也可以检测全部主域名和子域名。</div>
      <div class="toolbar"><button class="secondary" id="checkCurrentRootDns">当前主域名DNS检查</button><button class="secondary globalAdminOnly" id="checkEveryDns">全部域名DNS检查</button><button class="secondary" id="exportCurrentDns">导出当前Cloudflare配置</button></div>
      <div class="logBox" id="dnsBulkLog" style="margin-top:8px"></div>
    </div>"""
        admin_ops_block = """
    <div class="box hidden adminOnly globalAdminOnly adminPanelSection" data-admin-section="ops" id="adminOpsBox">
      <div class="sectionTitle">系统运维</div>
      <div class="toolbar"><button class="secondary" id="checkHealth">健康检查</button><button class="secondary" id="createBackup">手动备份</button><button class="secondary" id="loadBackups">备份列表</button><button class="secondary" id="loadAudit">审计日志</button><button class="secondary" id="exportAudit">导出审计</button><button class="secondary" id="loadFailures">异常记录</button><button class="secondary" id="loadCleanupRuns">清理记录</button></div>
      <div class="logBox" id="adminOpsLog" style="margin-top:8px"></div>
    </div>
      </section>
    </div>"""
    body = (
        MAIL_REVIEW_HTML
        .replace("__ADMIN_BLOCK__", admin_block)
        .replace("__ADMIN_OPS_BLOCK__", admin_ops_block)
        .replace("__DOMAIN__", html.escape(domain))
        .replace("__BRAND_TITLE__", html.escape(brand_title))
        .replace("__BRAND_DESC__", html.escape(brand_desc))
        .replace("__DEFAULT_ALIAS__", html.escape(default_alias))
        .replace("__BASE_DOMAIN__", html.escape(root_domain))
        .replace("__DEFAULT_ROOT_DOMAIN__", html.escape(DOMAIN))
        .replace("__PUBLIC_IP__", html.escape(PUBLIC_IP))
        .replace("__TENANT_STYLE__", tenant_style)
    )
    return body


def _host_without_port(value):
    host = str(value or "").strip().lower()
    if not host:
        return ""
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    return host.split(":", 1)[0]


def host_allowed(value):
    host = _host_without_port(value)
    if not host:
        return False
    if host in TRUSTED_HOSTS:
        return True
    for item in TRUSTED_HOSTS:
        if item.startswith("*.") and host.endswith(item[1:]) and host != item[2:]:
            return True
    return False


def origin_allowed(value):
    origin = str(value or "").strip().rstrip("/")
    if not origin:
        return False
    return origin in CORS_ALLOWED_ORIGINS


def security_headers(content_type=""):
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cache-Control": "no-store",
    }
    if "text/html" in str(content_type).lower():
        headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'none'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "frame-src 'self' data: blob:; "
            "form-action 'self'"
        )
    return headers


def redacted_log_message(message):
    msg = str(message or "")
    msg = re.sub(r"(?i)(authorization|x-token|token|key)=([^&\s]+)", r"\1=[redacted]", msg)
    msg = re.sub(r"(/code/)alias_[A-Za-z0-9_-]+", r"\1[redacted]", msg)
    return msg[:800]


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "FerretMailAPI/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def log_message(self, fmt, *args):
        request_line = str(args[0] if args else "")
        parts = request_line.split()
        method = parts[0][:12] if parts else str(getattr(self, "command", "") or "")[:12]
        target = parts[1] if len(parts) > 1 else str(getattr(self, "path", "") or "")
        path = urlparse(target).path
        if path.startswith("/code/"):
            path = "/code/[redacted]"
        status = str(args[1] if len(args) > 1 else "")[:12]
        safe_log(f"http {method} {path[:500]} {status}".strip())

    def client_ip(self):
        try:
            return str(self.client_address[0] or "")
        except Exception:
            return "unknown"

    def check_host(self):
        if host_allowed(self.headers.get("Host") or ""):
            return True
        self.send_json({"code": 421, "message": "host not allowed"}, 421)
        return False

    def check_rate(self, scope, limit, window=60):
        ok, retry = rate_check(f"{scope}:{self.client_ip()}", limit, window)
        if ok:
            return True
        self.send_json({"code": 429, "message": "too many requests", "retryAfter": retry}, 429)
        return False

    def check_body_limit(self):
        transfer_encoding = (self.headers.get("transfer-encoding") or "").strip().lower()
        if transfer_encoding and transfer_encoding != "identity":
            self.send_json({"code": 501, "message": "transfer encoding is not supported"}, 501)
            return False
        try:
            n = int(self.headers.get("content-length") or 0)
        except Exception:
            self.send_json({"code": 400, "message": "invalid content-length"}, 400)
            return False
        if n < 0:
            self.send_json({"code": 400, "message": "invalid content-length"}, 400)
            return False
        if n > API_MAX_BODY_BYTES:
            self.send_json({"code": 413, "message": "request body too large"}, 413)
            return False
        self._content_length = n
        return True

    def request_guard(self, mutation=False):
        if not self.check_host():
            return False
        if not self.check_rate("api-post" if mutation else "api", API_MUTATION_RATE_LIMIT_PER_MIN if mutation else API_RATE_LIMIT_PER_MIN):
            return False
        if mutation and not self.check_body_limit():
            return False
        return True

    def send_bytes(self, body, content_type="text/html; charset=utf-8", status=200, headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        response_headers = security_headers(content_type)
        response_headers.update(headers or {})
        content_type_lower = str(content_type or "").lower()
        accepts_gzip = "gzip" in (self.headers.get("Accept-Encoding") or "").lower()
        compressible = content_type_lower.startswith("text/") or "json" in content_type_lower or "svg+xml" in content_type_lower
        if accepts_gzip and compressible and len(body) >= 1024 and "Content-Encoding" not in response_headers:
            body = gzip.compress(body, compresslevel=5)
            response_headers["Content-Encoding"] = "gzip"
            response_headers["Vary"] = "Accept-Encoding"
        origin = self.headers.get("Origin") or ""
        if origin_allowed(origin):
            response_headers["Access-Control-Allow-Origin"] = origin.rstrip("/")
            vary = {item.strip() for item in str(response_headers.get("Vary") or "").split(",") if item.strip()}
            vary.add("Origin")
            response_headers["Vary"] = ", ".join(sorted(vary))
        self._response_started = True
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        for key, value in response_headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_bytes(body, "application/json; charset=utf-8", status)

    def read_body(self):
        n = int(getattr(self, "_content_length", self.headers.get("content-length") or 0))
        if n <= 0:
            return {}
        data = self.rfile.read(n)
        if len(data) != n:
            raise ValueError("incomplete request body")
        try:
            decoded = data.decode("utf-8")
            value = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("request body must be valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("request JSON must be an object")
        return value

    def authed(self):
        auth = self.headers.get("Authorization") or self.headers.get("X-Token") or ""
        if auth.lower().startswith("bearer "):
            auth = auth[7:].strip()
        return bool(PANEL_TOKEN) and constant_time_equal(auth, PANEL_TOKEN)

    def auth_context(self):
        auth = self.headers.get("Authorization") or self.headers.get("X-Token") or ""
        if auth.lower().startswith("bearer "):
            auth = auth[7:].strip()
        if PANEL_TOKEN and constant_time_equal(auth, PANEL_TOKEN):
            return {"role": "admin", "domain": ""}
        domain = get_domain_by_token(auth)
        if domain:
            return {"role": "root" if is_root_domain(domain) else "domain", "domain": domain}
        return None

    def require_auth(self):
        ctx = self.auth_context()
        if not ctx:
            ok, retry = rate_check(f"auth-fail:{self.client_ip()}", AUTH_FAIL_LIMIT, 600)
            if not ok:
                log_ok, _ = rate_check(f"auth-block-log:{self.client_ip()}", 1, 60)
                if log_ok:
                    log_op("", f"ip:{self.client_ip()}", "security.auth_blocked", {"path": urlparse(self.path).path, "retryAfter": retry})
                self.send_json({"code": 429, "message": "too many failed auth attempts", "retryAfter": retry}, 429)
                return False
            log_op("", f"ip:{self.client_ip()}", "security.auth_failed", {"path": urlparse(self.path).path})
            self.send_json({"code": 401, "message": "unauthorized"}, 401)
            return False
        self.auth = ctx
        return True

    def require_admin(self):
        if not self.require_auth():
            return False
        if self.auth.get("role") != "admin":
            self.send_json({"code": 403, "message": "admin token required"}, 403)
            return False
        return True

    def require_domain_manager(self):
        if not self.require_auth():
            return False
        if self.auth.get("role") not in ("admin", "root"):
            self.send_json({"code": 403, "message": "domain manager token required"}, 403)
            return False
        return True

    def can_manage_domain(self, domain):
        domain = normalize_domain(domain)
        if getattr(self, "auth", {}).get("role") == "admin":
            return True
        if getattr(self, "auth", {}).get("role") == "root":
            return domain_in_root(domain, self.auth.get("domain") or "")
        return False

    def auth_domain(self, requested="", default=DOMAIN):
        role = getattr(self, "auth", {}).get("role")
        if role == "domain":
            domain = self.auth["domain"]
            if requested and domain_input(requested) != domain:
                raise ValueError("domain token cannot access this domain")
            return domain
        if role == "root":
            root = self.auth["domain"]
            domain = normalize_domain(requested or default or root, root)
            if not domain_in_root(domain, root):
                raise ValueError("root domain token cannot access this domain")
            return domain
        return normalize_domain(requested or default)

    def ensure_email_allowed(self, email):
        email = normalize_addr(email)
        if not email:
            raise ValueError("email required")
        role = getattr(self, "auth", {}).get("role")
        if role == "domain":
            if not email.endswith("@" + self.auth["domain"]):
                raise ValueError("domain token cannot access this mailbox")
        elif role == "root":
            domain = domain_of_email(email)
            if not domain_in_root(domain, self.auth["domain"]):
                raise ValueError("root domain token cannot access this mailbox")
        elif not allowed_mailbox(email):
            raise ValueError("unsupported mail domain")
        return email

    def public_origin(self):
        if PUBLIC_BASE_URL:
            return PUBLIC_BASE_URL
        host = (self.headers.get("Host") or "").strip().split()[0]
        return f"http://{host}" if host else ""

    def require_alias_share(self, token, touch=True):
        token = normalize_alias_share_token(token)
        if not token:
            self.send_json({"code": 404, "message": "alias share link not found"}, 404)
            return None
        ip_ok, retry = rate_check(f"alias-share-ip:{self.client_ip()}", ALIAS_SHARE_RATE_LIMIT_PER_MIN, 60)
        if not ip_ok:
            self.send_json({"code": 429, "message": "too many alias share requests", "retryAfter": retry}, 429)
            return None
        tok_ok, retry = rate_check(f"alias-share-token:{sha256_hex(token)[:24]}", ALIAS_SHARE_TOKEN_RATE_LIMIT_PER_MIN, 60)
        if not tok_ok:
            self.send_json({"code": 429, "message": "too many alias share token requests", "retryAfter": retry}, 429)
            return None
        data = get_alias_by_share_token(token, touch=touch)
        if not data:
            self.send_json({"code": 404, "message": "alias share link not found or disabled"}, 404)
            return None
        return data

    def _dispatch(self, callback):
        self._response_started = False
        try:
            callback()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True
        except socket.timeout:
            self.close_connection = True
            if not self._response_started:
                self.send_json({"code": 408, "message": "request timeout"}, 408)
        except PermissionError as exc:
            if not self._response_started:
                self.send_json({"code": 403, "message": str(exc)}, 403)
        except ValueError as exc:
            if not self._response_started:
                self.send_json({"code": 400, "message": str(exc)}, 400)
        except Exception as exc:
            safe_log(f"http handler error path={urlparse(str(self.path or '')).path[:500]} type={type(exc).__name__}: {exc}")
            self.close_connection = True
            if not self._response_started:
                self.send_json({"code": 500, "message": "internal server error"}, 500)

    def do_OPTIONS(self):
        self._dispatch(self._do_OPTIONS)

    def do_HEAD(self):
        self._dispatch(self._do_HEAD)

    def do_GET(self):
        self._dispatch(self._do_GET)

    def do_POST(self):
        self._dispatch(self._do_POST)

    def _do_HEAD(self):
        path = urlparse(self.path).path
        public_paths = {
            "/", "/health", "/api-docs", "/api-docs.md", "/usage-guide", "/usage-guide.md",
            "/favicon.svg", "/favicon.ico", "/favicon.png", "/apple-touch-icon.png",
            "/mail", "/ui", "/inbox", "/mail/wenxin",
        }
        if path not in public_paths and not path.startswith("/mail/"):
            self._response_started = True
            self.send_response(405)
            self.send_header("Allow", "GET, POST, OPTIONS, HEAD")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._do_GET()

    def _do_OPTIONS(self):
        if not self.request_guard():
            return
        origin = self.headers.get("Origin") or ""
        if origin and not origin_allowed(origin):
            return self.send_json({"code": 403, "message": "origin not allowed"}, 403)
        self._response_started = True
        self.send_response(204)
        self.send_header("content-length", "0")
        self.send_header("access-control-allow-headers", "authorization,x-token,content-type")
        self.send_header("access-control-allow-methods", "GET,POST,OPTIONS")
        if origin_allowed(origin):
            self.send_header("access-control-allow-origin", origin.rstrip("/"))
            self.send_header("vary", "Origin")
        for key, value in security_headers("application/json").items():
            self.send_header(key, value)
        self.end_headers()

    def _do_GET(self):
        if not self.request_guard():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/favicon.svg":
            self.send_bytes(FAVICON_SVG, "image/svg+xml; charset=utf-8", headers={"Cache-Control": "public, max-age=86400"})
        elif path in ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png"):
            self.send_bytes(FAVICON_PNG, "image/png", headers={"Cache-Control": "public, max-age=86400"})
        elif path == "/":
            self.send_json({"ok": True, "service": "ferret-mail", "ui": "/mail"})
        elif path == "/health":
            report = health_report()
            public_report = {
                "ok": report["ok"],
                "status": report["status"],
                "service": "ferret-mail",
                "ui": "/mail",
                "checkedAt": report["checkedAt"],
                "components": {key: bool(value.get("ok")) for key, value in report["components"].items()},
            }
            self.send_json(public_report, 200 if report["ok"] else 503)
        elif path in ("/api-docs", "/api-docs.md"):
            self.send_bytes(
                api_docs_markdown(self.public_origin()),
                "text/markdown; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="ferret-mail-api-docs.md"', "Cache-Control": "no-store"},
            )
        elif path in ("/usage-guide", "/usage-guide.md"):
            self.send_bytes(
                usage_guide_markdown(self.public_origin()),
                "text/markdown; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="ferret-mail-usage-guide.md"', "Cache-Control": "no-store"},
            )
        elif path.startswith("/code/"):
            self.send_bytes(ALIAS_CODE_HTML)
        elif path == "/public-api/alias-share":
            query = parse_qs(parsed.query)
            share = self.require_alias_share((query.get("token") or [""])[0], touch=True)
            if not share:
                return
            try:
                rows, total, page, page_size = alias_share_public_messages(
                    share["email"],
                    query=(query.get("q") or [""])[0],
                    page=int((query.get("page") or [1])[0] or 1),
                    page_size=int((query.get("pageSize") or [50])[0] or 50),
                )
                with db() as con:
                    stats = con.execute("SELECT mail_count AS c,latest_mail_at AS latest FROM aliases WHERE email=?", (share["email"],)).fetchone()
                latest = int(stats["latest"] or 0) if stats else 0
                self.send_json({
                    "code": 200,
                    "message": "success",
                    "data": {
                        "email": share["email"],
                        "messages": rows,
                        "total": total,
                        "page": page,
                        "pageSize": page_size,
                        "latest": latest,
                        "mailboxCount": int(_row_get(stats, "c", 0) or 0),
                    },
                })
            except Exception as exc:
                self.send_json({"code": 400, "message": str(exc)}, 400)
        elif path == "/public-api/alias-share/message":
            query = parse_qs(parsed.query)
            share = self.require_alias_share((query.get("token") or [""])[0], touch=True)
            if not share:
                return
            try:
                mid = int((query.get("id") or [0])[0] or 0)
            except Exception:
                mid = 0
            with db() as con:
                row = con.execute("SELECT * FROM mails WHERE id=? AND to_email=?", (mid, share["email"])).fetchone()
            if not row:
                return self.send_json({"code": 404, "message": "message not found"}, 404)
            _html_body, links = _html_and_links_from_raw(row["raw"] or "", row["text"] or "")
            data = mail_row_json(row, include_body=True)
            data.update({"links": links})
            self.send_json({"code": 200, "message": "success", "data": data})
        elif path == "/public-api/alias-share/changes":
            if not self.check_rate("alias-share-long-poll", LONG_POLL_RATE_LIMIT_PER_MIN):
                return
            query = parse_qs(parsed.query)
            share = self.require_alias_share((query.get("token") or [""])[0], touch=False)
            if not share:
                return
            client_ip = self.client_ip()
            if not acquire_long_poll_slot(client_ip):
                return self.send_json({"code": 429, "message": "too many active realtime requests"}, 429)
            try:
                since = int((query.get("since") or [0])[0] or 0)
                deadline = time.time() + 25
                while time.time() < deadline:
                    snapshot = latest_mail_snapshot(domain_of_email(share["email"]), share["email"])
                    if int(snapshot["latest"] or 0) > since:
                        break
                    wait_for_mail_change(min(25, max(0.1, deadline - time.time())))
                else:
                    snapshot = latest_mail_snapshot(domain_of_email(share["email"]), share["email"])
                self.send_json({"code": 200, "message": "success", "data": {**snapshot, "changed": int(snapshot["latest"] or 0) > since}})
            except Exception as exc:
                self.send_json({"code": 400, "message": str(exc)}, 400)
            finally:
                release_long_poll_slot(client_ip)
        elif path in ("/mail", "/ui", "/inbox"):
            self.send_bytes(mail_html(DOMAIN))
        elif path == "/mail/wenxin":
            self.send_bytes(mail_html(f"wenxin.{DOMAIN}"))
        elif path.startswith("/mail/"):
            try:
                self.send_bytes(mail_html(path.rsplit("/", 1)[-1]))
            except Exception:
                self.send_json({"code": 404, "message": "not found"}, 404)
        elif path == "/ui-api/auth-check":
            if not self.require_auth(): return
            self.send_json({
                "code": 200,
                "message": "success",
                "data": {
                    "role": self.auth.get("role"),
                    "domain": self.auth.get("domain") or DOMAIN,
                    "canManageDomains": self.auth.get("role") in ("admin", "root"),
                    "canAddRootDomains": self.auth.get("role") == "admin",
                },
            })
        elif path == "/ui-api/aliases":
            if not self.require_auth(): return
            query = parse_qs(parsed.query)
            try:
                requested_domain = (query.get("domain") or [""])[0]
                page = int((query.get("page") or [1])[0] or 1)
                page_size = int((query.get("pageSize") or [50])[0] or 50)
                search = (query.get("q") or [""])[0]
                if self.auth.get("role") in ("domain", "root"):
                    domain_filter = self.auth_domain(requested_domain, "")
                else:
                    domain_filter = normalize_domain(requested_domain or DOMAIN)
                rows, total, page, page_size = list_aliases_page(domain_filter, search, page, page_size)
            except Exception as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            self.send_json({
                "code": 200,
                "message": "success",
                "data": [
                    dict(
                        email=r["email"],
                        note=r["note"] or "",
                        createdAt=r["created_at"],
                        count=r["count"],
                        latest=r["latest"],
                        shareEnabled=bool(r["share_enabled"]),
                        sharePath=alias_share_path(r["share_token"] or "") if r["share_enabled"] else "",
                        shareCreatedAt=r["share_created_at"],
                        shareLastUsedAt=r["share_last_used_at"],
                    )
                    for r in rows
                ],
                "total": total,
                "page": page,
                "pageSize": page_size,
                "domain": domain_filter,
            })
        elif path == "/ui-api/domains":
            if not self.require_auth(): return
            query = parse_qs(parsed.query)
            page = max(1, int((query.get("page") or [1])[0] or 1))
            page_size = max(1, min(int((query.get("pageSize") or [50])[0] or 50), 100))
            search = ((query.get("q") or [""])[0] or "").lower().strip()
            try:
                current_root = root_domain_for(domain_input((query.get("root") or [""])[0] or DOMAIN)) or DOMAIN
            except Exception:
                current_root = DOMAIN
            if self.auth.get("role") == "root":
                current_root = self.auth["domain"]
            offset = (page - 1) * page_size
            with db() as con:
                if self.auth.get("role") == "domain":
                    rows = con.execute("""
                    SELECT d.*,
                           COALESCE(u.alias_count,0) AS alias_count,
                           COALESCE(u.mail_count,0) AS mail_count,
                           COALESCE(u.storage_bytes,0) AS storage_bytes,
                           (SELECT MAX(m.received_at) FROM mails m WHERE m.domain=d.domain) AS latest
                    FROM mail_domains d
                    LEFT JOIN domain_usage u ON u.domain=d.domain
                    WHERE d.domain=?
                    """, (self.auth["domain"],)).fetchall()
                    total = len(rows)
                else:
                    where_parts = ["(d.domain=? OR d.domain LIKE ?)"]
                    params = [current_root, "%." + current_root]
                    if search:
                        where_parts.append("(LOWER(d.domain) LIKE ? OR LOWER(COALESCE(d.note,'')) LIKE ? OR LOWER(COALESCE(d.owner,'')) LIKE ?)")
                        like = "%" + search + "%"
                        params.extend([like, like, like])
                    where = " AND ".join(where_parts)
                    total = con.execute(f"SELECT COUNT(*) AS c FROM mail_domains d WHERE {where}", params).fetchone()["c"]
                    rows = con.execute("""
                    SELECT d.*,
                           COALESCE(u.alias_count,0) AS alias_count,
                           COALESCE(u.mail_count,0) AS mail_count,
                           COALESCE(u.storage_bytes,0) AS storage_bytes,
                           (SELECT MAX(m.received_at) FROM mails m WHERE m.domain=d.domain) AS latest
                     FROM mail_domains d
                     LEFT JOIN domain_usage u ON u.domain=d.domain
                     WHERE """ + where + """
                     ORDER BY CASE WHEN d.domain=? THEN 0 ELSE 1 END, d.domain
                     LIMIT ? OFFSET ?
                """, params + [current_root, page_size, offset]).fetchall()
            root_token_items = []
            if self.auth.get("role") == "admin":
                roots = root_domains(refresh=True)
                with db() as con:
                    root_rows = {}
                    for root in roots:
                        row = con.execute("SELECT domain,note,owner,token,enabled,token_disabled FROM mail_domains WHERE domain=?", (root,)).fetchone()
                        stats = con.execute("""
                            SELECT
                              (SELECT COUNT(*) FROM mail_domains d WHERE d.domain LIKE ?) AS subdomain_count,
                              (SELECT COALESCE(SUM(alias_count),0) FROM domain_usage u WHERE u.domain=? OR u.domain LIKE ?) AS alias_count,
                              (SELECT COALESCE(SUM(mail_count),0) FROM domain_usage u WHERE u.domain=? OR u.domain LIKE ?) AS mail_count,
                              (SELECT MAX(m.received_at) FROM mails m WHERE m.domain=? OR m.domain LIKE ?) AS latest
                        """, ("%." + root, root, "%." + root, root, "%." + root, root, "%." + root)).fetchone()
                        root_rows[root] = {"row": row, "stats": stats}
                root_tabs = []
                for root in roots:
                    packed = root_rows.get(root) or {}
                    row = packed.get("row")
                    stats = packed.get("stats")
                    tab_item = {"domain": root, "path": domain_path(root), "active": root == current_root}
                    token_item = dict(tab_item)
                    token_item.update({
                        "subdomainCount": int(stats["subdomain_count"] or 0) if stats else 0,
                        "aliasCount": int(stats["alias_count"] or 0) if stats else 0,
                        "mailCount": int(stats["mail_count"] or 0) if stats else 0,
                        "latest": stats["latest"] if stats else None,
                        "mxName": mx_name_for(root),
                        "mxServer": mail_host_for(root),
                        "mxPriority": 10,
                        "mailAName": "mail",
                        "mailAValue": PUBLIC_IP,
                    })
                    if row:
                        token_item.update({
                            "note": row["note"] or "",
                            "owner": row["owner"] or "",
                            "token": row["token"] or "",
                            "enabled": bool(row["enabled"]),
                            "tokenDisabled": bool(row["token_disabled"]),
                        })
                    else:
                        token_item.update({"note": "", "owner": "", "token": "", "enabled": True, "tokenDisabled": False})
                    root_tabs.append(tab_item)
                    root_token_items.append(token_item)
            elif self.auth.get("role") == "root":
                root_tabs = [{"domain": current_root, "path": domain_path(current_root), "active": True}]
            else:
                root_tabs = []
            data = [
                {
                    "domain": r["domain"],
                    "path": domain_path(r["domain"]),
                    "rootDomain": root_domain_for(r["domain"]),
                    "isRootDomain": is_root_domain(r["domain"]),
                    "note": r["note"] or "",
                    "owner": r["owner"] or "",
                    "createdAt": r["created_at"],
                    "aliasCount": r["alias_count"],
                    "mailCount": r["mail_count"],
                    "storageBytes": r["storage_bytes"],
                    "latest": r["latest"],
                    "enabled": bool(r["enabled"]),
                    "tokenDisabled": bool(r["token_disabled"]),
                    "retentionHours": r["retention_hours"],
                    "cleanupMaxMails": r["cleanup_max_mails"],
                    "aliasLimit": r["alias_limit"],
                    "mailLimit": r["mail_limit"],
                    "storageLimitMb": r["storage_limit_mb"],
                    "brandTitle": r["brand_title"] or "",
                    "brandDesc": r["brand_desc"] or "",
                    "defaultAlias": r["default_alias"] or "",
                    "themeColor": r["theme_color"] or "",
                    "webhookUrl": r["webhook_url"] or "",
                    "webhookEnabled": bool(r["webhook_enabled"]),
                    "mxName": mx_name_for(r["domain"]),
                    "mxServer": mail_host_for(r["domain"]),
                    "mxPriority": 10,
                    "mailAName": "mail",
                    "mailAValue": PUBLIC_IP,
                    "token": (r["token"] or "") if self.auth.get("role") in ("admin", "root") else "",
                    "canManageDomains": self.auth.get("role") in ("admin", "root"),
                }
                for r in rows
            ]
            self.send_json({"code": 200, "message": "success", "data": data, "total": total, "page": page, "pageSize": page_size, "role": self.auth.get("role"), "domain": self.auth.get("domain") or "", "root": current_root, "rootDomains": root_tabs, "rootDomainTokens": root_token_items, "canManageDomains": self.auth.get("role") in ("admin", "root"), "canAddRootDomains": self.auth.get("role") == "admin"})
        elif path == "/ui-api/messages":
            if not self.require_auth(): return
            query = parse_qs(parsed.query)
            try:
                domain = self.auth_domain((query.get("domain") or [""])[0], DOMAIN)
                email = (query.get("email") or [""])[0]
                if email:
                    self.ensure_email_allowed(email)
                filters = {
                    "from": (query.get("from") or [""])[0],
                    "subject": (query.get("subject") or [""])[0],
                    "to": (query.get("to") or [""])[0],
                    "code": (query.get("code") or [""])[0],
                    "hasCode": (query.get("hasCode") or [""])[0] == "1",
                    "hasLink": (query.get("hasLink") or [""])[0] == "1",
                    "unread": (query.get("unread") or [""])[0] == "1",
                    "today": (query.get("today") or [""])[0] == "1",
                    "starred": (query.get("starred") or [""])[0] == "1",
                    "pinned": (query.get("pinned") or [""])[0] == "1",
                    "dateFrom": (query.get("dateFrom") or [""])[0],
                    "dateTo": (query.get("dateTo") or [""])[0],
                }
                rows, total, page, page_size = list_messages_page(
                    domain,
                    email=email,
                    query=(query.get("q") or [""])[0],
                    page=int((query.get("page") or [1])[0] or 1),
                    page_size=int((query.get("pageSize") or [50])[0] or 50),
                    filters=filters,
                )
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            self.send_json({"code": 200, "message": "success", "data": rows, "total": total, "page": page, "pageSize": page_size})
        elif path == "/ui-api/changes":
            if not self.require_auth(): return
            if not self.check_rate("long-poll", LONG_POLL_RATE_LIMIT_PER_MIN):
                return
            client_ip = self.client_ip()
            if not acquire_long_poll_slot(client_ip):
                return self.send_json({"code": 429, "message": "too many active realtime requests"}, 429)
            query = parse_qs(parsed.query)
            try:
                domain = self.auth_domain((query.get("domain") or [""])[0], DOMAIN)
                email = normalize_addr((query.get("email") or [""])[0])
                if email:
                    self.ensure_email_allowed(email)
                    if not email.endswith("@" + domain):
                        raise ValueError("email domain mismatch")
                since = int((query.get("since") or [0])[0] or 0)
                deadline = time.time() + 25
                while time.time() < deadline:
                    snapshot = latest_mail_snapshot(domain, email)
                    if int(snapshot["latest"] or 0) > since:
                        break
                    wait_for_mail_change(min(25, max(0.1, deadline - time.time())))
                else:
                    snapshot = latest_mail_snapshot(domain, email)
                self.send_json({"code": 200, "message": "success", "data": {**snapshot, "changed": int(snapshot["latest"] or 0) > since}})
            except Exception as exc:
                self.send_json({"code": 400, "message": str(exc)}, 400)
            finally:
                release_long_poll_slot(client_ip)
        elif path == "/ui-api/message":
            if not self.require_auth(): return
            mid = int((parse_qs(parsed.query).get("id") or [0])[0] or 0)
            with db() as con:
                row = con.execute("SELECT * FROM mails WHERE id=?", (mid,)).fetchone()
            if not row:
                return self.send_json({"code": 404, "message": "not found"}, 404)
            try:
                self.ensure_email_allowed(row["to_email"])
            except Exception as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            allowed_domain = scope_for_auth(self.auth)
            set_messages_state([mid], {"isRead": True}, allowed_domain)
            with db() as con:
                row = con.execute("SELECT * FROM mails WHERE id=?", (mid,)).fetchone()
            html_body, links = _html_and_links_from_raw(row["raw"] or "", row["text"] or "")
            data = mail_row_json(row, include_body=True)
            data.update({"html": html_body, "links": links, "raw": row["raw"] or "", "headers": message_headers(row["raw"] or ""), "attachments": message_attachments(row["id"])})
            self.send_json({"code": 200, "message": "success", "data": data})
        elif path == "/ui-api/attachment":
            if not self.require_auth(): return
            aid = int((parse_qs(parsed.query).get("id") or [0])[0] or 0)
            with db() as con:
                row = con.execute("""
                    SELECT a.*,m.to_email FROM attachments a
                    JOIN mails m ON m.id=a.mail_id
                    WHERE a.id=?
                """, (aid,)).fetchone()
            if not row or row["data"] is None:
                return self.send_json({"code": 404, "message": "attachment not found"}, 404)
            try:
                self.ensure_email_allowed(row["to_email"])
            except Exception as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            filename = re.sub(r"[^A-Za-z0-9._-]+", "_", row["filename"] or "attachment").strip("._") or "attachment"
            self.send_bytes(row["data"], row["content_type"] or "application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
        elif path == "/ui-api/dns-check":
            if not self.require_auth(): return
            try:
                domain = self.auth_domain((parse_qs(parsed.query).get("domain") or [""])[0], DOMAIN)
                self.send_json({"code": 200, "message": "success", "data": dns_check(domain)})
            except Exception as exc:
                self.send_json({"code": 400, "message": str(exc)}, 400)
        elif path == "/ui-api/dns-check-bulk":
            if not self.require_domain_manager(): return
            query = parse_qs(parsed.query)
            scope = (query.get("scope") or ["current"])[0]
            try:
                if self.auth.get("role") == "admin" and scope == "all":
                    domains = list_domains(refresh=True)
                else:
                    root = (query.get("root") or [""])[0] or (self.auth.get("domain") if self.auth.get("role") == "root" else DOMAIN)
                    root = root_domain_for(domain_input(root)) or DOMAIN
                    if self.auth.get("role") == "root" and root != self.auth["domain"]:
                        raise PermissionError("root domain token cannot check another main domain")
                    domains = domains_under_root(root)
                self.send_json({"code": 200, "message": "success", "data": dns_check_many(domains)})
            except PermissionError as exc:
                self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                self.send_json({"code": 400, "message": str(exc)}, 400)
        elif path == "/ui-api/domain-export":
            if not self.require_domain_manager(): return
            query = parse_qs(parsed.query)
            kind = (query.get("type") or ["current-tokens"])[0]
            try:
                include_tokens = kind in ("root-tokens", "current-tokens")
                include_dns = kind in ("dns-current", "dns-all")
                if kind == "root-tokens":
                    if self.auth.get("role") != "admin":
                        raise PermissionError("admin token required")
                    domains = root_domains(refresh=True)
                elif kind == "dns-all":
                    if self.auth.get("role") == "admin":
                        domains = list_domains(refresh=True)
                    else:
                        domains = domains_under_root(self.auth["domain"])
                else:
                    root = (query.get("root") or [""])[0] or (self.auth.get("domain") if self.auth.get("role") == "root" else DOMAIN)
                    root = root_domain_for(domain_input(root)) or DOMAIN
                    if self.auth.get("role") == "root" and root != self.auth["domain"]:
                        raise PermissionError("root domain token cannot export another main domain")
                    domains = domains_under_root(root)
                lines = domain_export_lines(domains, self.public_origin(), include_tokens=include_tokens, include_dns=include_dns)
                filename = "domains-" + re.sub(r"[^A-Za-z0-9._-]+", "_", kind) + ".txt"
                self.send_bytes("\n".join(lines) + ("\n" if lines else ""), "text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
            except PermissionError as exc:
                self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                self.send_json({"code": 400, "message": str(exc)}, 400)
        elif path == "/ui-api/admin/overview":
            if not self.require_domain_manager(): return
            query = parse_qs(parsed.query)
            root = (query.get("root") or [""])[0] or DOMAIN
            if self.auth.get("role") == "root":
                root = self.auth["domain"]
            self.send_json({"code": 200, "message": "success", "data": admin_overview(root)})
        elif path == "/ui-api/admin/health":
            if not self.require_admin(): return
            self.send_json({"code": 200, "message": "success", "data": health_report(force=True)})
        elif path == "/ui-api/admin/backups":
            if not self.require_admin(): return
            self.send_json({"code": 200, "message": "success", "data": list_backups(), "totalBytes": backup_total_size(), "limitBytes": MAX_BACKUP_BYTES})
        elif path == "/ui-api/admin/backup-download":
            if not self.require_admin(): return
            try:
                name = (parse_qs(parsed.query).get("name") or [""])[0]
                path_name = backup_path_by_name(name)
                body = Path(path_name).read_bytes()
                self.send_bytes(body, "application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{os.path.basename(path_name)}"'})
            except Exception as exc:
                self.send_json({"code": 404, "message": str(exc)}, 404)
        elif path == "/ui-api/admin/audit":
            if not self.require_admin(): return
            query = parse_qs(parsed.query)
            domain = (query.get("domain") or [""])[0]
            params = []
            where = "1=1"
            if domain:
                where = "domain=?"
                params.append(domain_input(domain))
            with db() as con:
                rows = con.execute(f"SELECT * FROM operation_logs WHERE {where} ORDER BY created_at DESC LIMIT 500", params).fetchall()
            if (query.get("format") or [""])[0] == "csv":
                out = io.StringIO()
                w = csv.writer(out)
                w.writerow(["id", "domain", "actor", "action", "detail", "created_at"])
                for r in rows:
                    w.writerow([r["id"], r["domain"], r["actor"], r["action"], r["detail"], r["created_at"]])
                self.send_bytes(out.getvalue(), "text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=audit.csv"})
            else:
                self.send_json({"code": 200, "message": "success", "data": [dict(r) for r in rows]})
        elif path == "/ui-api/admin/failed-mails":
            if not self.require_admin(): return
            with db() as con:
                rows = con.execute("SELECT * FROM failed_mails ORDER BY created_at DESC LIMIT 200").fetchall()
            self.send_json({"code": 200, "message": "success", "data": [dict(r) for r in rows]})
        elif path == "/ui-api/admin/cleanup-runs":
            if not self.require_admin(): return
            with db() as con:
                rows = con.execute("SELECT * FROM cleanup_runs ORDER BY created_at DESC LIMIT 100").fetchall()
            self.send_json({"code": 200, "message": "success", "data": [dict(r) for r in rows]})
        else:
            self.send_json({"code": 404, "message": "not found"}, 404)

    def _do_POST(self):
        if not self.request_guard(mutation=True):
            return
        path = urlparse(self.path).path
        if path in ("/public/addUser", "/api/public/addUser"):
            if not self.require_admin():
                return
            body = self.read_body()
            items = body.get("list") if isinstance(body.get("list"), list) else []
            values = [item.get("email") if isinstance(item, dict) else item for item in items]
            try:
                result = save_aliases(values, "panel", DOMAIN)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            return self.send_json({"code": 200, "message": "success", "data": True, "result": result})
        if path in ("/public/emailList", "/api/public/emailList"):
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                to_email = self.ensure_email_allowed(body.get("toEmail") or body.get("email") or "")
            except Exception as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            size = max(1, min(int(body.get("size") or 20), 50))
            with db() as con:
                rows = con.execute(
                    "SELECT * FROM mails WHERE to_email=? ORDER BY pinned DESC, starred DESC, received_at DESC LIMIT ?",
                    (to_email, size),
                ).fetchall()
            data = [mail_row_json(r, include_body=False) for r in rows]
            return self.send_json({"code": 200, "message": "success", "data": data})
        if path == "/ui-api/aliases":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                domain = self.auth_domain(body.get("domain") or "", DOMAIN)
                alias_value = body.get("email") or body.get("prefix") or ""
                if self.auth.get("role") == "domain" and "@" in str(alias_value):
                    self.ensure_email_allowed(alias_value)
                em = alias_email(alias_value, domain)
                if not em.endswith("@" + domain):
                    raise ValueError("alias domain mismatch")
                em = save_alias(em, body.get("note") or "", domain)
            except Exception as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            log_op(domain, actor_label(self.auth), "alias.add", {"email": em})
            return self.send_json({"code": 200, "message": "success", "data": {"email": em}})
        if path == "/ui-api/bulk-aliases":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                domain = self.auth_domain(body.get("domain") or "", DOMAIN)
                aliases = body.get("aliases") if isinstance(body.get("aliases"), list) else body.get("list")
                result = save_aliases(aliases or [], body.get("note") or "batch", domain)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain, actor_label(self.auth), "alias.bulk_add", result)
            return self.send_json({"code": 200, "message": "success", "data": result})
        if path == "/ui-api/message-state":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                allowed_domain = scope_for_auth(self.auth)
                ids = body.get("ids") if isinstance(body.get("ids"), list) else [body.get("id") or body.get("messageId")]
                values = {}
                for key in ("isRead", "starred", "pinned"):
                    if key in body:
                        values[key] = bool(body.get(key))
                changed = set_messages_state(ids, values, allowed_domain)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(allowed_domain or "", actor_label(self.auth), "message.state", {"ids": len(ids), "values": values, "changed": changed})
            return self.send_json({"code": 200, "message": "success", "changed": changed})
        if path == "/ui-api/messages-bulk":
            if not self.require_auth():
                return
            body = self.read_body()
            action = str(body.get("action") or "").strip()
            ids = body.get("ids") if isinstance(body.get("ids"), list) else []
            allowed_domain = scope_for_auth(self.auth)
            try:
                if action == "delete":
                    changed = bulk_delete_messages(ids, allowed_domain)
                elif action == "read":
                    changed = set_messages_state(ids, {"isRead": True}, allowed_domain)
                elif action == "unread":
                    changed = set_messages_state(ids, {"isRead": False}, allowed_domain)
                elif action == "star":
                    changed = set_messages_state(ids, {"starred": True}, allowed_domain)
                elif action == "unstar":
                    changed = set_messages_state(ids, {"starred": False}, allowed_domain)
                elif action == "pin":
                    changed = set_messages_state(ids, {"pinned": True}, allowed_domain)
                elif action == "unpin":
                    changed = set_messages_state(ids, {"pinned": False}, allowed_domain)
                else:
                    return self.send_json({"code": 400, "message": "unsupported bulk action"}, 400)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(allowed_domain or "", actor_label(self.auth), "message.bulk_" + action, {"ids": len(ids), "changed": changed})
            return self.send_json({"code": 200, "message": "success", "changed": changed})
        if path == "/ui-api/domains-bulk":
            if not self.require_domain_manager():
                return
            body = self.read_body()
            try:
                root = body.get("root") or (self.auth.get("domain") if self.auth.get("role") == "root" else DOMAIN)
                root = root_domain_for(domain_input(root)) or DOMAIN
                if self.auth.get("role") == "root" and root != self.auth["domain"]:
                    raise PermissionError("root domain token cannot add another main domain")
                result = bulk_save_subdomains(body.get("domains") or body.get("list") or "", root, body.get("owner") or "", bool(body.get("issueTokens")))
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(root, actor_label(self.auth), "domain.bulk_create", {"created": len(result["created"]), "existing": len(result["existing"]), "errors": len(result["errors"]), "issueTokens": bool(body.get("issueTokens"))})
            return self.send_json({"code": 200, "message": "success", "data": result})
        if path == "/ui-api/domains":
            if not self.require_domain_manager():
                return
            body = self.read_body()
            try:
                default_root = body.get("root") or (self.auth.get("domain") if self.auth.get("role") == "root" else DOMAIN)
                candidate = domain_input(body.get("domain") or body.get("subdomain") or "", default_root)
                if self.auth.get("role") == "root" and not domain_in_root(candidate, self.auth["domain"]):
                    raise PermissionError("root domain token cannot add another main domain")
                domain = save_domain(
                    candidate,
                    body.get("note") or "panel",
                    default_root,
                )
                if body.get("owner"):
                    update_domain_settings(domain, {"owner": body.get("owner")})
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain, actor_label(self.auth), "domain.create", {"domain": domain})
            return self.send_json({
                "code": 200,
                "message": "success",
                "data": {
                    "domain": domain,
                    "path": domain_path(domain),
                    "mxName": mx_name_for(domain),
                    "mxServer": mail_host_for(domain),
                    "mxPriority": 10,
                    "mailAName": "mail",
                    "mailAValue": PUBLIC_IP,
                },
            })
        if path == "/ui-api/domain-settings":
            if not self.require_domain_manager():
                return
            body = self.read_body()
            try:
                domain = normalize_domain(body.get("domain") or "")
                if not self.can_manage_domain(domain):
                    raise PermissionError("cannot manage this domain")
                disabling = body.get("enabled") is False or str(body.get("enabled") or "").strip().lower() in {"0", "false", "no", "off"}
                if disabling:
                    with db() as con:
                        current = con.execute("SELECT enabled FROM mail_domains WHERE domain=?", (domain,)).fetchone()
                    if current and int(current["enabled"] or 0) and str(body.get("confirmDomain") or "").strip().lower() != domain:
                        return self.send_json({"code": 400, "message": "domain confirmation required"}, 400)
                cfg = update_domain_settings(domain, body)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain, actor_label(self.auth), "domain.settings", {k: body.get(k) for k in body.keys() if k != "token"})
            return self.send_json({"code": 200, "message": "success", "data": cfg})
        if path == "/ui-api/domain-token":
            if not self.require_domain_manager():
                return
            body = self.read_body()
            try:
                domain = normalize_domain(body.get("domain") or "")
                if not self.can_manage_domain(domain):
                    raise PermissionError("cannot manage this domain")
                token = set_domain_token(domain, body.get("token") or "")
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain, actor_label(self.auth), "domain.token_reset", {"domain": domain})
            return self.send_json({"code": 200, "message": "success", "data": {"domain": domain, "token": token, "path": domain_path(domain)}})
        if path == "/ui-api/delete-domain":
            if not self.require_domain_manager():
                return
            body = self.read_body()
            try:
                domain = normalize_domain(body.get("domain") or "")
                if not domain:
                    raise ValueError("domain required")
                if not self.can_manage_domain(domain):
                    raise PermissionError("cannot manage this domain")
                root_domain = root_domain_for(domain, refresh=True) or domain
                is_root = domain == root_domain
                if str(body.get("confirm") or "").strip().lower() != domain:
                    return self.send_json({"code": 400, "message": "domain confirmation required"}, 400)
                expected_phrase = "删除主域名" if is_root else "删除子域名"
                if str(body.get("phrase") or "").strip() != expected_phrase:
                    return self.send_json({"code": 400, "message": "phrase confirmation required"}, 400)
                if is_root and self.auth.get("role") != "admin":
                    raise PermissionError("admin token required to delete main domain")
                if is_root and domain == DOMAIN:
                    raise ValueError("default main domain cannot be deleted")
                create_backup("pre-delete-domain")
                result = delete_domain_tree(domain, self.auth)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain, actor_label(self.auth), "domain.delete", result)
            return self.send_json({"code": 200, "message": "success", "data": result})
        if path == "/ui-api/alias-share-token":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                domain = self.auth_domain(body.get("domain") or "", DOMAIN)
                email = alias_email(body.get("email") or "", domain)
                if not email.endswith("@" + domain):
                    raise ValueError("alias domain mismatch")
                enabled = bool(body.get("enabled", True))
                reset = bool(body.get("reset"))
                data = ensure_alias_share(email, domain, reset=reset, enabled=enabled)
                data["url"] = (self.public_origin() + data["path"]) if data.get("path") else ""
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            action = "alias.share_disable" if not data.get("enabled") else ("alias.share_reset" if reset else "alias.share_enable")
            log_op(domain, actor_label(self.auth), action, {"email": email})
            response_data = dict(data)
            response_data.pop("token", None)
            return self.send_json({"code": 200, "message": "success", "data": response_data})
        if path == "/ui-api/alias-share-export":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                domain = self.auth_domain(body.get("domain") or "", DOMAIN)
                lines = export_alias_share_urls(domain, self.public_origin())
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain, actor_label(self.auth), "alias.share_export", {"count": len(lines)})
            filename = "alias-code-links-" + re.sub(r"[^A-Za-z0-9._-]+", "_", domain) + ".txt"
            body_text = "\n".join(lines) + ("\n" if lines else "")
            return self.send_bytes(body_text, "text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{filename}"', "X-Export-Count": str(len(lines))})
        if path == "/ui-api/delete-alias":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                domain = self.auth_domain(body.get("domain") or "", DOMAIN)
                email = alias_email(body.get("email") or "", domain)
                if not email.endswith("@" + domain):
                    raise ValueError("alias domain mismatch")
                if str(body.get("confirm") or "").strip().lower() != email:
                    return self.send_json({"code": 400, "message": "alias confirmation required"}, 400)
                allowed_domain = scope_for_auth(self.auth)
                email, deleted = delete_alias(email, domain, allowed_domain)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain, actor_label(self.auth), "alias.delete", {"email": email, "deleted": deleted})
            return self.send_json({"code": 200, "message": "success", "data": {"email": email, "deleted": deleted}})
        if path == "/ui-api/delete-message":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                allowed_domain = scope_for_auth(self.auth)
                deleted = delete_mail(body.get("id") or body.get("messageId"), allowed_domain)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(allowed_domain or "", actor_label(self.auth), "message.delete", {"deleted": deleted})
            return self.send_json({"code": 200, "message": "success", "deleted": deleted})
        if path == "/ui-api/clear-alias-messages":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                email = self.ensure_email_allowed(body.get("email") or "")
                if str(body.get("confirm") or "").strip().lower() != email:
                    return self.send_json({"code": 400, "message": "email confirmation required"}, 400)
                allowed_domain = scope_for_auth(self.auth)
                create_backup("pre-clear")
                deleted = clear_alias_mails(email, allowed_domain)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain_of_email(email), actor_label(self.auth), "message.clear_alias", {"email": email, "deleted": deleted})
            return self.send_json({"code": 200, "message": "success", "deleted": deleted})
        if path == "/ui-api/clear-messages":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                domain = self.auth_domain(body.get("domain") or DOMAIN, DOMAIN)
                if str(body.get("confirm") or "").strip().lower() != domain:
                    return self.send_json({"code": 400, "message": "domain confirmation required"}, 400)
                allowed_domain = scope_for_auth(self.auth)
                create_backup("pre-clear")
                deleted = clear_domain_mails(domain, allowed_domain)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain, actor_label(self.auth), "message.clear_domain", {"deleted": deleted})
            return self.send_json({"code": 200, "message": "success", "deleted": deleted})
        if path == "/ui-api/clear-aliases":
            if not self.require_auth():
                return
            body = self.read_body()
            try:
                domain = self.auth_domain(body.get("domain") or DOMAIN, DOMAIN)
                if str(body.get("confirm") or "").strip().lower() != domain:
                    return self.send_json({"code": 400, "message": "domain confirmation required"}, 400)
                if str(body.get("phrase") or "").strip() != "清空别名":
                    return self.send_json({"code": 400, "message": "phrase confirmation required"}, 400)
                allowed_domain = scope_for_auth(self.auth)
                create_backup("pre-clear")
                deleted = clear_domain_aliases(domain, allowed_domain)
            except PermissionError as exc:
                return self.send_json({"code": 403, "message": str(exc)}, 403)
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            log_op(domain, actor_label(self.auth), "alias.clear_domain", {"deleted": deleted})
            return self.send_json({"code": 200, "message": "success", "deleted": deleted})
        if path in ("/admin/cleanup", "/api/admin/cleanup"):
            if not self.require_admin():
                return
            deleted = cleanup_old()
            log_op(DOMAIN, "admin", "cleanup.manual", {"deleted": deleted})
            return self.send_json({"code": 200, "message": "success", "deleted": deleted})
        if path == "/ui-api/admin/backup-create":
            if not self.require_admin():
                return
            try:
                data = create_backup("manual")
            except ValueError as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            return self.send_json({"code": 200, "message": "success", "data": data})
        if path == "/ui-api/admin/backup-restore":
            if not self.require_admin():
                return
            body = self.read_body()
            if str(body.get("confirm") or "").strip() != "恢复备份":
                return self.send_json({"code": 400, "message": "restore confirmation required"}, 400)
            if str(body.get("confirmName") or "").strip() != str(body.get("name") or "").strip():
                return self.send_json({"code": 400, "message": "backup name confirmation required"}, 400)
            try:
                data = restore_backup(body.get("name") or "")
            except Exception as exc:
                return self.send_json({"code": 400, "message": str(exc)}, 400)
            return self.send_json({"code": 200, "message": "success", "data": data})
        self.send_json({"code": 404, "message": "not found"}, 404)

class SMTPConn:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")
        self.mail_from = ""
        self.mail_started = False
        self.rcpts = []
        self.command_count = 0

    async def send(self, line):
        self.writer.write((line + "\r\n").encode())
        await asyncio.wait_for(self.writer.drain(), timeout=30)

    async def close(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    async def readline(self):
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=SMTP_IDLE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            await self.send("421 idle timeout")
            return None
        except (ValueError, asyncio.LimitOverrunError):
            await self.send("500 command line too long")
            return None
        if not data:
            return None
        return data.decode("utf-8", errors="replace").rstrip("\r\n")

    def reset_transaction(self):
        self.mail_from = ""
        self.mail_started = False
        self.rcpts = []

    async def handle(self):
        await self.send(f"220 mail.{DOMAIN} ESMTP ready")
        while True:
            line = await self.readline()
            if line is None:
                break
            self.command_count += 1
            if self.command_count > SMTP_COMMAND_LIMIT:
                await self.send("421 too many commands")
                break
            cmd = line.split(" ", 1)[0].upper()
            arg = line[len(cmd):].strip()
            if cmd == "EHLO":
                self.reset_transaction()
                await self.send(f"250-mail.{DOMAIN}")
                await self.send(f"250-SIZE {MAX_MESSAGE_BYTES}")
                await self.send("250-8BITMIME")
                await self.send("250 SMTPUTF8")
            elif cmd == "HELO":
                self.reset_transaction()
                await self.send(f"250 mail.{DOMAIN}")
            elif cmd == "MAIL":
                try:
                    declared_size = re.search(r"(?:^|\s)SIZE=(\d+)(?:\s|$)", arg, re.I)
                    if declared_size and int(declared_size.group(1)) > MAX_MESSAGE_BYTES:
                        await self.send("552 message too large")
                        continue
                    self.mail_from = smtp_path(arg, "FROM", allow_empty=True)
                except ValueError:
                    await self.send("501 invalid sender path")
                    continue
                self.mail_started = True
                self.rcpts = []
                await self.send("250 OK")
            elif cmd == "RCPT":
                if not self.mail_started:
                    await self.send("503 need MAIL first")
                    continue
                try:
                    rcpt = smtp_path(arg, "TO")
                except ValueError:
                    await self.send("501 invalid recipient path")
                    continue
                if rcpt in self.rcpts:
                    await self.send("250 OK")
                    continue
                if len(self.rcpts) >= SMTP_MAX_RCPTS_PER_MESSAGE:
                    log_failed_mail(self.mail_from, rcpt, "too many recipients")
                    await self.send("452 too many recipients")
                    continue
                if allowed_mailbox(rcpt, for_receipt=True):
                    self.rcpts.append(rcpt)
                    await self.send("250 OK")
                else:
                    log_failed_mail(self.mail_from, rcpt, "relay not permitted or quota exceeded")
                    await self.send("550 relay not permitted")
            elif cmd == "DATA":
                if not self.mail_started or not self.rcpts:
                    await self.send("503 need MAIL and RCPT first")
                    continue
                await self.send("354 end with <CRLF>.<CRLF>")
                chunks = []
                total = 0
                complete = False
                while True:
                    try:
                        data = await asyncio.wait_for(self.reader.readline(), timeout=SMTP_DATA_TIMEOUT_SECONDS)
                    except asyncio.TimeoutError:
                        await self.send("421 data timeout")
                        await self.close()
                        return
                    if not data:
                        break
                    if data in (b".\r\n", b".\n"):
                        complete = True
                        break
                    if data.startswith(b".."):
                        data = data[1:]
                    total += len(data)
                    if total > MAX_MESSAGE_BYTES:
                        await self.send("552 message too large")
                        await self.close()
                        return
                    chunks.append(data)
                if not complete:
                    await self.close()
                    return
                raw = b"".join(chunks)
                recipients = list(self.rcpts)
                response = "250 queued"
                try:
                    await asyncio.to_thread(store_mails, self.mail_from, recipients, raw)
                except ValueError as exc:
                    response = "552 message rejected"
                    for rcpt in recipients:
                        log_failed_mail(self.mail_from, rcpt, "message rejected", str(exc))
                except Exception as exc:
                    response = "451 temporary local problem"
                    for rcpt in recipients:
                        log_failed_mail(self.mail_from, rcpt, "temporary store failure", str(exc))
                self.reset_transaction()
                await self.send(response)
            elif cmd == "RSET":
                self.reset_transaction()
                await self.send("250 OK")
            elif cmd == "NOOP":
                await self.send("250 OK")
            elif cmd == "QUIT":
                await self.send("221 bye")
                break
            else:
                await self.send("502 command not implemented")
        await self.close()

async def smtp_handler(reader, writer):
    if not _SMTP_SLOTS.acquire(blocking=False):
        try:
            writer.write(b"421 server busy, try again later\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return
    try:
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip = str(peer[0] or "unknown")
        ok, _ = rate_check(f"smtp-conn:{ip}", SMTP_CONN_RATE_LIMIT_PER_MIN, 60)
        if not ok:
            try:
                writer.write(b"421 too many connections\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return
        try:
            await SMTPConn(reader, writer).handle()
        except Exception as exc:
            safe_log(f"smtp error type={type(exc).__name__}: {exc}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    finally:
        _SMTP_SLOTS.release()


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 128

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(max(5, HTTP_REQUEST_TIMEOUT_SECONDS))
        return request, client_address

    def process_request(self, request, client_address):
        if not _HTTP_SLOTS.acquire(blocking=False):
            try:
                body = b'{"code":503,"message":"server busy"}'
                response = (
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json; charset=utf-8\r\n"
                    b"Connection: close\r\n"
                    b"Retry-After: 5\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    + body
                )
                request.sendall(response)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            _HTTP_SLOTS.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            _HTTP_SLOTS.release()


def validate_runtime_config():
    errors = []
    if not PANEL_TOKEN or len(PANEL_TOKEN) < 24 or PANEL_TOKEN.upper().startswith(("CHANGE_ME", "YOUR_")):
        errors.append("PANEL_TOKEN must be a non-placeholder secret of at least 24 characters")
    if not DOMAIN or not domain_format_valid(DOMAIN):
        errors.append("MAIL_DOMAIN is invalid")
    if not ROOT_DOMAINS or any(not domain_format_valid(domain) for domain in ROOT_DOMAINS):
        errors.append("MAIL_ROOT_DOMAINS contains an invalid domain")
    if not TRUSTED_HOSTS:
        errors.append("TRUSTED_HOSTS must not be empty")
    for name, value, low, high in (
        ("HTTP_PORT", HTTP_PORT, 1, 65535),
        ("SMTP_PORT", SMTP_PORT, 1, 65535),
        ("HTTP_MAX_CONNECTIONS", HTTP_MAX_CONNECTIONS, 8, 4096),
        ("SMTP_MAX_CONNECTIONS", SMTP_MAX_CONNECTIONS, 1, 1024),
        ("HTTP_REQUEST_TIMEOUT_SECONDS", HTTP_REQUEST_TIMEOUT_SECONDS, 5, 600),
        ("SMTP_IDLE_TIMEOUT_SECONDS", SMTP_IDLE_TIMEOUT_SECONDS, 30, 1800),
        ("SMTP_DATA_TIMEOUT_SECONDS", SMTP_DATA_TIMEOUT_SECONDS, 30, 1800),
        ("MAX_BACKUPS", MAX_BACKUPS, 2, 10000),
        ("AUTO_BACKUP_HOURS", AUTO_BACKUP_HOURS, 1, 8760),
        ("BACKUP_MAX_AGE_HOURS", BACKUP_MAX_AGE_HOURS, 1, 17520),
    ):
        if not low <= int(value) <= high:
            errors.append(f"{name} must be between {low} and {high}")
    if MAX_MESSAGE_BYTES <= 0:
        errors.append("MAX_MESSAGE_BYTES must be positive")
    if MAX_ATTACHMENT_BYTES < 0 or MAX_ATTACHMENT_BYTES > MAX_MESSAGE_BYTES:
        errors.append("MAX_ATTACHMENT_BYTES must be between 0 and MAX_MESSAGE_BYTES")
    if MIN_DISK_FREE_BYTES < 64 * 1024 * 1024:
        errors.append("MIN_DISK_FREE_BYTES must be at least 67108864")
    if PUBLIC_BASE_URL:
        parsed = urlparse(PUBLIC_BASE_URL)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            errors.append("PUBLIC_BASE_URL must be an absolute http(s) origin without credentials, query, or fragment")
    for origin in CORS_ALLOWED_ORIGINS:
        parsed = urlparse(origin)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            errors.append(f"CORS_ALLOWED_ORIGINS contains an invalid origin: {origin[:120]}")
    if errors:
        raise RuntimeError("invalid configuration: " + "; ".join(errors))


def run_http(httpd):
    safe_log(f"http listening on {HTTP_HOST}:{HTTP_PORT}")
    httpd.serve_forever()

async def cleanup_loop():
    while True:
        await asyncio.sleep(3600)
        try:
            deleted = cleanup_old()
            if deleted:
                safe_log(f"cleanup deleted={deleted}")
            housekeeping_deleted = cleanup_housekeeping()
            if housekeeping_deleted:
                safe_log(f"housekeeping deleted={housekeeping_deleted}")
            ensure_auto_backup()
            db_maintenance()
        except Exception as exc:
            safe_log(f"cleanup error: {exc}")

async def main():
    validate_runtime_config()
    integrity = database_integrity_check(force=True)
    if not integrity.get("ok"):
        raise RuntimeError(integrity.get("message") or "database integrity check failed")
    ensure_auto_backup()
    httpd = BoundedThreadingHTTPServer((HTTP_HOST, HTTP_PORT), ApiHandler)
    try:
        server = await asyncio.start_server(smtp_handler, SMTP_HOST, SMTP_PORT)
    except BaseException:
        httpd.server_close()
        raise
    Thread(target=run_http, args=(httpd,), daemon=True, name="ferret-http").start()
    safe_log(f"smtp listening on {SMTP_HOST}:{SMTP_PORT} domains={','.join(list_domains())}")
    Thread(target=backfill_message_metadata, daemon=True, name="mail-metadata-backfill").start()
    asyncio.create_task(cleanup_loop())
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())


