#!/bin/bash

# don't use
export uid token

# urls
request_token_url="https://lulu.lulufind.com/mrzy/mrzypc/getQiniuTokenV2"
upload_file_url="https://upload-z2.qiniup.com/"
download_file_url="https://img2.lulufind.com/"

# other constants
file_upload_prefix="file/other/student/"

function get_upload_sign()
{
    # $1: target filename
    # return: upload sign

    # Generation mode:
    # get the base64 of '{"keys":"<target filename>"}'
    # concatenate with IF75D4U19LKLDAZSMPN5ATQLGBFEJL4VIL2STVDBNJJTO6LNOGB265CR40I4AL13
    # and md5sum
    a="$(
        (echo -n "{\"keys\":\"$1\"}" | base64 -w0
         echo -n IF75D4U19LKLDAZSMPN5ATQLGBFEJL4VIL2STVDBNJJTO6LNOGB265CR40I4AL13) |
         md5sum
    )"
    echo "${a% *}"
}

function get_upload_filename()
{
    # $1: source filename
    # $2: uid
    # return: target filename

    # target filename: <file upload prefix><current unix timestamp>_<UID>_<random 0~99999999>_[.<extension>]
    printf "%s%u_%s_%u_%s" "$file_upload_prefix" "$(date +%s)" "$2" $(( (RANDOM << 12) % 99999999 )) "$(expr "$1" : ".*\(\..*\)")"
    # printf "%s%u_%s_%u_orig_%s_%s" "$file_upload_prefix" "$(date +%s)" "$2" $(( (RANDOM << 12) % 99999999 )) "$1" "$(expr "$1" : ".*\(\..*\)")"
}

function get_upload_token()
{
    # $1: target filename
    # $2: upload sign
    # $3: user token
    # return: upload token

    resp=$(curl \
           -f \
           -s \
           -S \
           -L \
           --compressed \
           -H "token: $3" \
           -H "sign: $2" \
           --data-urlencode "keys=$1" \
           "$request_token_url"
    )
    if [ $? != 0 -o "$(echo "$resp" | jq -r ".code")" != 200 ]
    then
        echo "Error while fetching upload token for file '$1'." >&2
        echo -n "Error information: " >&2
        echo "$resp" >&2
        return 1
    fi
    echo "$resp" | jq -r ".data.\"$1\""
}

function upload_file()
{
    # $1: source filename
    # $2: target filename
    # $3: upload token
    # return: none

    # we want user to see the upload progress,
    # so we don't use -sS
    resp=$(curl \
           -f \
           -v \
           -L \
           --compressed \
           -F "token=$3" \
           -F "key=$2" \
           -F "file=@$1" \
           "$upload_file_url"
    )
    if [ $? != 0 -o "$(echo "$resp" | jq -r ".error")" != null ]
    then
        echo "Error while uploading file '$1'." >&2
        echo -n "Error information: " >&2
        echo "$resp" >&2
        return 1
    fi
}

function upload_file_front()
{
    # $1: source file name
    # $2: user token
    # $3: uid
    # $4: file mimetype (maybe none)
    # $5: remote filename (maybe none)
    # return: none

    if [ ! -e "$1" ]
    then
        echo "File '$1' doesn't exist!" >&2
        return 1
    fi

    if [ -d "$1" ]
    then
        echo "Do not use directory '$1' as file name!" >&2
        return 1
    fi

    if [ -n "$4" ]
    then
        mimetype="$4"
    else
        if command -v mimetype >/dev/null
        then
            mimetype="$(mimetype -b -L "$1")"
        else
            mimetype=""
        fi
    fi

    if [ -n "$5" ]
    then
        echo "Warning: You're manually specifying remote file name," >&2
        echo "which may cause conflicts!" >&2
        rfilename="$5"
    else
        rfilename="$(get_upload_filename "$1" "$3")"
    fi

    echo "Uploading file '$1' to '$download_file_url$rfilename'..."
    upload_sign="$(get_upload_sign "$rfilename")"
    if ! upload_token="$(get_upload_token "$rfilename" "$upload_sign" "$2")"
    then
        return 1
    fi

    printf \
"Upload info:
    Filename: %s
    Type: %s
    Location: %s%s
    Sign: %s
    Token: %s
" "$1" "$mimetype" "$download_file_url" "$rfilename" "$upload_sign" "$upload_token" >&2

    if ! upload_file "$1" "$rfilename" "$upload_token"
    then
        return 1
    fi

    echo "File '$1' has been uploaded to '$download_file_url$rfilename'."
}

function mrzy_login()
{
    # $1: username (maybe none)
    # $2: password (maybe none)
    # return: none (sets global variable `token' and `uid')

    if [ -z "$1" ]
    then
        read -p "Input username: " username
    else
        username="$1"
    fi

    if [ -z "$2" ]
    then
        read -p "Input password (will not be echoed): " -s password
        echo
    else
        password="$2"
    fi

    echo "Logging into MeiRiZuoYe..."

    # Content-Type: application/json is required
    resp=$(curl \
           -f \
           -s \
           -S \
           -L \
           --compressed \
           -H "Content-Type: application/json" \
           --data "{\"login\":\"$username\",\"password\":\"$password\"}" \
           "https://api-prod.lulufind.com/api/v1/auth/pwdlogin"
    )

    if [ $? != 0 -o "$(echo "$resp" | jq -r ".code")" != 200 ]
    then
        echo "Error while logging into MeiRiZuoYe."
        echo -n "Error information: "
        echo "$resp"
        return 1
    fi

    echo "Logged on."

    token="$(echo "$resp" | jq -r ".data.token")"
    uid="$(echo "$resp" | jq -r ".data.openId")"
}

function usage()
{
    echo "Usage: $0 [-h|--help] [-u <USERNAME>] [-p <PASSWORD>] [-s <PASSFILE>] -f <FILENAME> [-t <MIMETYPE>] [-r <RFILENAME>] [-f <FILE> ...]" >&2
    echo "Upload files to MeiRiZuoYe.">&2
    echo >&2
    echo "Note: before using this tool, make sure" >&2
    echo "you have bound a password account!" >&2
    echo >&2
    echo "  -u <USERNAME>    Username for login" >&2
    echo "  -p <PASSWORD>    Password for login" >&2
    echo "  -s <PASSFILE>    File with username and password" >&2
    echo "       (format: <username> <password>)" >&2
    echo "  -f <FILENAME>    File to upload" >&2
    echo "  -t <MIMETYPE>    The type of file, in MIME" >&2
    echo "  -r <RFILENAME>   Remote file name" >&2
    echo "       (be careful when using this option," >&2
    echo "        you may overwrite other files!)" >&2
    echo "  -h, --help       Display this help" >&2
}

if [ $# -lt 1 ]
then
    usage
    exit 1
fi

tasks=()

# I wish this could work
eval set -- "$(getopt -l help -o hu:p:s:f:t:r: -- "$@")"
current_task=""
while true
do
    case "$1" in
        -h|--help) usage; exit;;
        -u) username="$2"; shift 2;;
        -p) password="$2"; shift 2;;
        -s) read username password <"$2"; shift 2;;
        -f)
            current_task="task_$(date +%s)_$RANDOM"
            tasks+=("$current_task")
            eval "${current_task}_filename"="$2"
            eval "${current_task}_mimetype"=""
            eval "${current_task}_rfilename"=""
            shift 2
            ;;
        -t) eval "${current_task}_mimetype"="$2"; shift 2;;
        -r) eval "${current_task}_rfilename"="$2"; shift 2;;
        --) shift; break;;
        *)
            echo "Unknown option: $1" >&2
            usage; exit 1
            ;;
    esac
done

if [ ${#tasks} = 0 ]
then
    usage
    exit 1
fi

mrzy_login "$username" "$password"

for task in "${tasks[@]}"
do
    eval upload_file_front \""\$${task}_filename"\" \""$token"\" \""$uid"\" \""\$${task}_mimetype"\" \""\$${task}_rfilename"\"
done
