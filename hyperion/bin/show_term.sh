#!/bin/bash

if [ $# -lt 1 ]
  then
    # Incorrect amount of arguments supplied
    echo "$@"
    exit 1
fi

args=("$@")

script_dir="$(dirname "${BASH_SOURCE[0]}")/show_session.sh $1"
echo $script_dir

comp_name=${args[0]}

if [ $# -eq 2 ]
  then
    host=${args[1]}
    echo "Launching xterm to attach remote session"
    xterm -e "ssh -t $host 'bash -c \"tmux attach-session -t $comp_name\"'"
else
    echo "Launching xterm to attach local session"
    xterm -e "$script_dir $comp_name"
fi

exit 0