#!/bin/bash

if [ $# -ne 1 ]
  then
    # Incorrect amount of arguments supplied
    echo "-1"
    exit 1
fi

args=("$@")
echo $args

script_dir="$(dirname "${BASH_SOURCE[0]}")/show_session.sh $1"
echo $script_dir

echo "Launching xterm to attach session"
xterm -hold -e "$script_dir $args"

exit 0