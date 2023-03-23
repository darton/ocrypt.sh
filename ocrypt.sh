#!/usr/bin/env bash


case "$1" in

    'encrypt')
        /usr/bin/openssl enc -aes-256-cbc -md sha512 -pbkdf2 -iter 1000000 -salt -in "$2" -out "$3"
    ;;
    'decrypt')
        /usr/bin/openssl enc -aes-256-cbc -md sha512 -pbkdf2 -iter 1000000 -salt -in "$2" -out "$3" -d
    ;;

     *)
        echo -e "\nUsage: ocrypt.sh encrypt InputFilePath OutputFilePath |ocrypt.sh decrypt InputFilePath OutputFilePath"
    ;;
    esac
