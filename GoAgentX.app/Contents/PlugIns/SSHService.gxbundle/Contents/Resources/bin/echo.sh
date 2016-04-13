#!/bin/bash
prompt=$1
check_yesno=${prompt/yes\/no/}
(( len = ${#prompt} - ${#check_yesno} ))
if [ $len == 6 ]; then
    echo yes
else
    echo $ECHO_CONTENT
fi
