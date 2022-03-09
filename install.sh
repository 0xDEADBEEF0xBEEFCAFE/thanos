#!/bin/sh

cd $(cd -P -- "$(dirname -- "$0")" && pwd -P)

if ! command -v gcc >/dev/null 2>&1; then
  echo 'Please install gcc.'
  exit 1
fi

gcc dnsflood.c -o thanos &&\
sudo ln -sf "${PWD}/thanos" /usr/local/bin/thanos

if [ $? -ne 0 ]; then
  echo 'Error installing.'
else
  echo 'Installation successful:'
fi
ls -lha /usr/local/bin/thanos

