#!/bin/bash

get_file_offset()
{
	SYM="$(readelf -sW "$1" | grep " $2"'@@' |awk '{print $2}')"
	readelf -lW "$1" | grep '  LOAD' | awk '{printf ("x=0x'"$SYM"'\nif %s <= x < %s+%s: print \"%%x\" %% (x+%s-%s)\n", $3,$3,$5,$2,$3)}' |python
}

resolve_hook()
{
	OFFSET=$(get_file_offset "$1" "$2")
	echo "$1" "$OFFSET"
}

resolve_hook "$1" "$2"

