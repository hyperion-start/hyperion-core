#!/bin/bash

export TMUX=""

if [ -z $TMUX ]
  then
  echo "not in a tmux env yet, starting with attach to session"
  tmux attach-session -t "$1"
else
  echo "Already in tmux session, switching to correct session"
  tmux switch-client -t "$1"
fi