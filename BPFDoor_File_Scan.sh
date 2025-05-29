echo -e "\n[ Scan Start ]"
echo "------------------------------------------------------------------ "

echo -e "[ Stage 0 ] Root Priviliege  Check"
if [ "$EUID" -ne 0 ]; then
    echo "- You need to have Root Priviliege "
    exit 1
else
	echo " OK!!"
fi

target_dir=$1
scanner_path=$0

echo -e "\n[ Stage 1 ] BPFDoor Check"
Match=$(find $target_dir -path /proc -prune -o -path /sys -prune -o -type f -size -4M -exec sh -c 'strings "$1" | grep -Eq "ttcompat|:h:d:l:s:b:t" && echo "$1"' _ {} \;)
if [ -n "$Match" ]; then
	for sus_file in $Match; do
		rule1=$(hexdump -ve '1/1 "%02x"' $sus_file | grep -o "c6459049c6459135c645922ac6459341c6459459c6459562")

		if [ -n "$rule1" ]; then
			check_file+=' '$sus_file
			continue
		fi

		rule2=$(strings $sus_file | grep -o ":wiu")
		
		if [ -n "$rule2" ]; then
			check_file+=' '$sus_file
			continue
		fi

		rule3=$(strings $sus_file | grep -o "127.0.0.1")

		if [ -n "$rule3" ]; then
			rule4=$(strings $sus_file | grep -o "RC4-MD5")
			if [ -n "$rule4" ]; then
				check_file+=' '$sus_file
				continue
			fi
		fi	
	done
fi

mal_count=0

for mal_file in $check_file; do
    if [ "$mal_file" == "$scanner_path" ]; then
		continue
	else
		echo " "$mal_file
        let mal_count=mal_count+1
	fi
done

if [ "$mal_count" -eq 0 ]; then
	echo " OK!!"
fi


echo -e "\n******* [ Total Result ] ********"
echo " - Total Malicious:"$mal_count
echo "------------------------------------------------------------------ "
echo "[ Scan Finish ]"
echo -e "\n"