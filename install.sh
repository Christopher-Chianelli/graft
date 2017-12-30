#!/bin/sh
while getopts ":d:yn" opt; do
  case $opt in
    d)
      GRAFT_DATA_DIR="$OPTARG"
      ;;
    y)
      DEFAULT_ANSWER="y"
      ;;
    n)
      DEFAULT_ANSWER="n"
      ;;
    :)
      echo "Option -$OPTARG requires a path to put the data directory." >&2
      exit 1
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

if [ -n "$GRAFT_DATA_DIR" ]
then
  : #DO NOTHING
elif [ -n "$XDG_DATA_HOME" ]
then
  GRAFT_DATA_DIR="$XDG_DATA_HOME/graft"
elif [ -n "$HOME" ]
then
  GRAFT_DATA_DIR="$HOME/.local/share/graft"
else
  GRAFT_DATA_DIR="/usr/share/graft"
fi

if [ -d "$GRAFT_DATA_DIR" ]
then
  make
elif mkdir -p -m "700" "$GRAFT_DATA_DIR"
then
  make
else
  echo "Could not create $GRAFT_DATA_DIR"
  exit 1;
fi
