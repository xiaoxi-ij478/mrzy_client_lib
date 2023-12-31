#!/usr/bin/env python3

import base64
import collections
import datetime
import getopt
import hashlib
import io
import json
import mimetypes
import os.path
import random
import sys
import time
import traceback
import urllib.request

UPLOAD_SPLIT_CHUNK_SIZE = 6 * 1024 * 1024

class LoginError(Exception):
    "Error while logging in."

class APIError(Exception):
    "Error while communicating with API."

def get_upload_sign(json_data):
    return hashlib.md5(
        base64.b64encode(
            json.dumps(
                json_data,
                separators=(',', ':')
            ).encode()
        ) +
        b"IF75D4U19LKLDAZSMPN5ATQLGBFEJL4VIL2STVDBNJJTO6LNOGB265CR40I4AL13"
    ).hexdigest()

def get_default_upload_filename(src_filename, user_token):
    # (work|file)/(image|audio|video|other)/(student|teacher|other)/....
    return "file/other/student/{}_{}_{}_{}".format(
        int(time.time()),
        # for privacy
        "u0000000000000000",
        random.randint(0, 99999999),
        os.path.splitext("" if src_filename == 0 else src_filename)[1]
    )

def get_upload_token(rmt_filename, upload_sign, get_token_api, user_token):
    # 'getQiniuTokenV2' supports only (work|file)/(image|audio|video|other)/(student|teacher|other)/....
    # 'getQiniuToken' supports arbitrary path

    result_json = json.load(
        urllib.request.urlopen(
            urllib.request.Request(
                "https://lulu.lulufind.com/mrzy/mrzypc/getQiniuToken" + ("V2" if get_token_api == 2 else ""),
                headers={
                    "token": user_token,
                    "sign": upload_sign
                },
                data=f"keys={rmt_filename}".encode()
            )
        )
    )

    if result_json["code"] != 200:
        raise APIError("Error while fetching upload token.")

    return result_json["data"][rmt_filename]

# from ikunpan.py
_roll_pos = 0
_minus = True
def print_progress(cur_size, total_size, speed):
    global _roll_pos
    global _minus

    if total_size == 0:
        tbar = (' ' * _roll_pos) + "<=>" + (' ' * (24 - _roll_pos))
        if _roll_pos == 24 or _roll_pos == 0:
            _minus = not _minus

        if _minus:
            _roll_pos -= 1
        else:
            _roll_pos += 1
    else:
        pbar = int(27 * (cur_size / total_size))
        tbar = '=' * (pbar - 1) + '>' * bool(pbar)

    res_str = "     {:>6}[{:<27}]{:>35}     ".format(
        "" if not total_size else "{:.1f}%".format(cur_size / total_size * 100),
        tbar,
        "{} / {}  {}/s".format(
            size_to_human_readable(cur_size),
            size_to_human_readable(total_size),
            size_to_human_readable(speed)
        )
    )
    print(res_str, end='\r')

def size_to_human_readable(size):
    suffixes = ['B', "KiB", "MiB", "GiB", "TiB", "EiB", "ZiB", "YiB"]
    suffix = 0

    while size >= 1024 and suffix <= 7:
        size /= 1024
        suffix += 1

    return "{:.2f} {}".format(size, suffixes[suffix])

def upload_file(src_filename, rmt_filename, file_type, upload_token):
    if src_filename != 0:
        if not os.access(src_filename, os.R_OK):
            raise PermissionError(f"File {src_filename} can't be read!")

    base64_encoded_rmt_filename = base64.b64encode(rmt_filename.encode()).decode()
    file_type = file_type or mimetypes.guess_type("" if src_filename == 0 else src_filename)[0] or "application/octet-stream"

    print("Preparing upload...")
    post_upload_begin_json = json.load(
        urllib.request.urlopen(
            urllib.request.Request(
                "https://upload-z2.qiniup.com/"
                "buckets/mrzy/objects/{}/uploads".format(
                    base64_encoded_rmt_filename
                ),
                headers={"Authorization": "UpToken " + upload_token},
                data=b""
            )
        )
    )
    print(
        "Update expires at",
        datetime.datetime.fromtimestamp(post_upload_begin_json["expireAt"]).ctime()
    )

    multipart_upload_uploadid = post_upload_begin_json["uploadId"]

    file = open(src_filename, "rb")
    buffer = memoryview(bytearray(UPLOAD_SPLIT_CHUNK_SIZE))
    partnum = 0
    uploaded = 0
    etags = []

    if src_filename != 0:
        file.seek(0, io.SEEK_END)
        file_size = file.tell()
        file.seek(0, io.SEEK_SET)
    else:
        file_size = 0

    begin_time = time.time()
    print("Uploading...")
    while size := file.readinto(buffer):
        print_progress(uploaded, file_size, uploaded / (time.time() - begin_time))
        partnum += 1
        response_json = json.load(
            urllib.request.urlopen(
                urllib.request.Request(
                    "https://upload-z2.qiniup.com/"
                    "buckets/mrzy/objects/{}/uploads/{}/{}".format(
                        base64_encoded_rmt_filename,
                        multipart_upload_uploadid,
                        partnum
                    ),
                    data=buffer,
                    headers={
                        "Authorization": "UpToken " + upload_token,
                        "Content-Type": "application/octet-stream",
                        "Content-MD5": hashlib.md5(buffer[:size]).hexdigest(),
                        "Content-Length": size
                    },
                    method="PUT"
                )
            )
        )
        etags.append(response_json["etag"])
        uploaded += size

    print_progress(uploaded, file_size, uploaded / (time.time() - begin_time))
    print()

    # do not close stdin
    if src_filename != 0:
        file.close()

    multipart_complete_json = {
        "fname": rmt_filename,
        "mimeType": file_type,
        "parts": list(  
            map(
                lambda part_etag: {"etag": part_etag[1], "partNumber": part_etag[0] + 1},
                enumerate(etags)
            )
        )
    }

    multipart_complete_response_json = json.load(
        urllib.request.urlopen(
            urllib.request.Request(
                "https://upload-z2.qiniup.com/"
                "buckets/mrzy/objects/{}/uploads/{}".format(
                    base64_encoded_rmt_filename,
                    multipart_upload_uploadid
                ),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "UpToken " + upload_token
                },
                data=json.dumps(multipart_complete_json).encode()
            )
        )
    )

##    print("Commiting to mrzy...")
##    commit_to_mrzy(src_filename, rmt_filename, file_size, user_token)

    return "https://img2.lulufind.com/" + rmt_filename

def commit_to_mrzy(src_filename, rmt_filename, file_size, user_token):
    file_info = {
        "name": os.path.basename(src_filename),
        "type": os.path.splitext(src_filename)[1],
        "size": str(file_size),
        "fileUrl": "https://img2.lulufind.com/" + rmt_filename
    }

    result_json = json.load(
        urllib.request.urlopen(
            urllib.request.Request(
                "https://lulu.lulufind.com/mrzy/mrzypc/addUserFile",
                headers={
                    "token": user_token,
                    "sign": get_upload_sign(file_info)
                },
                data="&".join(map("=".join, file_info.items())).encode()
            )
        )
    )

    return result_json

def login_to_mrzy(username, password):
    print("Logging in...")

    response_json = json.load(
        urllib.request.urlopen(
            urllib.request.Request(
                "https://api-prod.lulufind.com/api/v1/auth/pwdlogin",
                headers={"Content-Type": "application/json"},
                data=json.dumps(
                    {"login": username, "password": password}
                ).encode()
            )
        )
    )

    if response_json["code"] != 200:
        raise LoginError("Error while logging in.")

    print("Logged in.")

    return response_json["data"]["token"]

def upload_front(src_filename, rmt_filename, file_type, get_token_api, user_token):
    if rmt_filename is None:
        rmt_filename = get_default_upload_filename(src_filename, user_token)

    print("Getting upload sign...")
    upload_sign = get_upload_sign({"keys": rmt_filename})

    print("Getting upload token...")
    upload_token = get_upload_token(rmt_filename, upload_sign, get_token_api, user_token)

    return upload_file(src_filename, rmt_filename, file_type, upload_token)

def print_help(prog_name):
    print(f"Usage: {prog_name} [OPTIONS]..")
    print("Upload files to MeiRiZuoYe.")
    print()
    print("Note: before using this tool, make sure")
    print("you have bound a password account!")
    print()
    print("  -u, --user           <USERNAME>   Username for login")
    print("  -p, --pass           <PASSWORD>   Password for login")
    print("  -s, --passfile       <PASSFILE>   File with username and password")
    print("         (format: <username> <password>)")
    print("  -f, --file           <FILENAME>   File to upload")
    print("         (use '-' to read from stdin)")
    print("  -t, --type           <MIMETYPE>   The type of file, in MIME")
    print("  -r, --remote         <RFILENAME>  Remote file name")
    print("         (be careful when using this option,")
    print("          you may overwrite other files!)")
    print("  -g, --get-token-api  <TYPE>       Get Token API to use (1/2, default 2)")
    print("         (With Get Token API v1 you can specify arbitrary remote path,")
    print("          and with Get Token API v2 you need to specify the remote path as follows:")
    print('          "(work|file)/(image|audio|video|other)/student|teacher|other)/<RFILENAME>")')
    print("         (BUT PERSONALLY I STRONGLY NOT RECOMMEND TO UPLOAD TO SOMETHING LIKE '/foo'!!!)")
    print("  -h, --help       Display this help")

def main(argc, argv):
    if argc == 1:
        print_help(argv[0])
        return 1

    username, password = None, None
    user_token = None
    file_entry = collections.namedtuple("FileEntry", "src_filename rmt_filename file_type get_token_api")
    command_line = getopt.getopt(
        argv[1:],
        "u:p:s:f:t:r:g:h",
        [
            "user=", "pass=",
            "passfile=", "file=",
            "type=", "remote=",
            "get-token-api=", "help"
        ]
    )
    file_to_upload = []

    for option, argument in command_line[0]:
        if option in ("-u", "--user"):
            username = argument

        elif option in ("-p", "--pass"):
            password = argument

        elif option in ("-s", "--passfile"):
            username, password = open(argument).readline().strip().split(maxsplit=1)

        elif option in ("-f", "--file"):
            if argument == '-':
                argument = 0

            file_to_upload.append(file_entry(argument, None, None, 2))

        elif option in ("-t", "--type"):
            file_to_upload[-1] = file_to_upload[-1]._replace(type=argument)

        elif option in ("-r", "--remote"):
            file_to_upload[-1] = file_to_upload[-1]._replace(rmt_filename=argument)

        elif option in ("-g", "--get-token-api"):
            if argument not in ('1', '2'):
                raise ValueError("Incorrent API version. Valid: 1, 2.")

            file_to_upload[-1] = file_to_upload[-1]._replace(get_token_api=int(argument))

        elif option in ("-h", "--help"):
            print_help(argv[0])
            return 0

    if username is None or password is None:
        print("Please specify username and password!")
        return 1

    user_token = login_to_mrzy(username, password)

    for file in file_to_upload:
        print(f"Uploading {'STDIN' if file.src_filename == 0 else file.src_filename}...")
        try:
            result = upload_front(
                file.src_filename, file.rmt_filename,
                file.file_type, file.get_token_api, user_token
            )
        except:
            print(f"Error while uploading file {'STDIN' if file.src_filename == 0 else file.src_filename}.")
            traceback.print_exc()
        else:
            print(f"File {'STDIN' if file.src_filename == 0 else file.src_filename} uploaded.")
            print(f"Link: {result}")

    return 0

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
