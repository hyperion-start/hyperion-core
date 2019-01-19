#!/bin/bash

if [ $# -ne 2 ]
  then
    # Incorrect amount of arguments supplied
    echo "-1"
    exit 1
fi

args=("$@")
session_name=${args[0]}
comp_name=${args[1]}

# "tmux has-session" seems to use incremental search which is stupid, because we want to know if the exact name exists yet
# so I am gonna do it my way
exists=`tmux list-sessions | grep -oE "$comp_name-clone-session"`
if [ ! -z $exists ]
  then
  echo "Clone session already exists"
  exit 1
fi

# Check if target window exists
winExists=`tmux list-windows -t "$session_name" | grep -oE "^([0-9][0-9]*: $comp_name)"`
if [ -z "$winExists" ]
  then
  tmux list-windows -t "$session_name"
  echo "No window was found"
  exit 2
fi

echo "found target window in main session"

# Set regex to find master session
regex=$session_name":.*group [0-9]*"

function find_master_group {
    echo "checking group for component $comp_name in session $session_name"
    tmux list-sessions
    tmux list-sessions | grep -oE "$regex"
    group=`tmux list-sessions | grep -oE "$regex" | grep -oE "[0-9]*$"`

    # Check if group was found
    if [ -z "$group" ]
      then
      echo "No Group was found"
    else
      found=1
    fi
}

find_master_group $session_name $comp_name
if [ -z $found ]
  then
  echo "Group not found. Staring clone session to assign group now"
  tmux new-session -d -t "$session_name"

  # Try again now
  find_master_group $session_name $comp_name
  if [ -z $found ]
    then
    echo "Group still not found. Exiting"
    exit 1
  else
    echo "Found master group"
  fi
else
  echo "Found master group"
  # Master session exists and clone session not found and master session has the correct window
  # thus it's safe to create a new clone session
  tmux new-session -d -t "$session_name"
fi

# Get clone session name within same group which is a number
ses_name=`tmux list-sessions | grep "group $group" | grep -oE "^([0-9][0-9]*:)"`

# Should be one session or none thus wc -l == 1
ses_count=`echo "$ses_name" | wc -l`
if [ "$ses_count" -ne 1 ]
  then
  echo "Too many sessions!"
  exit 1
fi

# Check if session was found
if [ -z "$ses_name" ]
  then
  echo "No session found"
  exit 1
fi

echo "clone session found"

# Remove trailing colon
ses_name_trimmed=${ses_name//:/}

# Rename the clone session
tmux rename-session -t "$ses_name_trimmed" "$comp_name-clone-session"

echo "renamed clone session to $ses_name_trimmed"

# Switch active window of the clone session to the desired one
tmux select-window -t "$comp_name-clone-session:$comp_name"

echo "set window active in clone session"
exit 0