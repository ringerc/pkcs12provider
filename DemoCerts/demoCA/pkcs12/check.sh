#!/bin/sh
set -e -u
for f in *.p12; do
	if openssl pkcs12 -in "$f" -nokeys -password "file:`basename $f .p12`.pass" >/dev/null ; then
		echo "$f OK"
	else
		echo "$f **** FAILED ****"
	fi
done
