#!/bin/bash

filesdir=$1

searchstr=$2

if [ -z ${filesdir} ] || [ -z ${searchstr} ]
then
	echo a parameter was not specified!
	exit 1
fi


if ! [ -e ${filesdir} ]
then
	echo the file does not exist!
	exit 1
fi


file_count=$(ls ${filesdir} -R | wc -l)

((file_count--))

pattern_count=$(grep -or ${searchstr} ${filesdir} | wc -l)

echo The number of files are ${file_count} and the number of matching lines are ${pattern_count}

exit 0
