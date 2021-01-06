#! /bin/sh
#***********************************************
#*                   genw.sh                   *
#***********************************************

server1=(cent70-1 192.168.137.80)
server2=(cent70-2 192.168.137.81)
server3=
server4=
server5=
server6=
server7=
server8=
server9=
server10=

ulimit -s unlimited
srvname=`clpstat --local | grep "*" | sed -E 's/[\t ]+\*//g' | sed -E 's/[\t ].*//g'`
path=/opt/nec/clusterpro/bin/clparping

if [ $srvname = $server1 ]; then
	$path ${server1[1]}
	ret=$?
elif [ $srvname = $server2 ]; then
        $path ${server2[1]}
	ret=$?
elif [ $srvname = $server3 ]; then
        $path ${server3[1]}
	ret=$?
elif [ $srvname = $server4 ]; then
        $path ${server4[1]}
	ret=$?
elif [ $srvname = $server5 ]; then
	$path ${server5[1]}
	ret=$?
elif [ $srvname = $server6 ]; then
	$path ${server6[1]}
	ret=$?
elif [ $srvname = $server7 ]; then
	$path ${server7[1]}
	ret=$?
elif [ $srvname = $server8 ]; then
	$path ${server8[1]}
	ret=$?
elif [ $srvname = $server9 ]; then
	$path ${server9[1]}
	ret=$?
elif [ $srvname = $server10 ]; then
	$path ${server10[1]}
	ret=$?
else
	ret=1
fi


exit $ret