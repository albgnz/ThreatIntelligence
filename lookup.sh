#!/usr/bin/env bash

function lookup {
      dir=`dirname $0`
      fgrep $1 $dir/*|cut -f1 -d:|uniq|rev|cut -f1 -d/|rev | fgrep -f - $dir/blocklists
}
      
if [ "x$1" == "x" ]; then
      while read IP; do
            echo "$IP"
            lookup $IP
      done
else
      lookup $1
fi

