echo -e "\n[ Scan Start ]"
echo "------------------------------------------------------------------ "

echo "[ Stage 0 ] Root Priviliege  Check"
if [ "$EUID" -ne 0 ]; then
	echo "- You need to have Root Priviliege "
	exit 1
else
	echo " OK!!"
fi

echo -e "\n[ Stage 1 ] BPFDoor Check"
Match=$(ss -0pb | grep -EB1 --colour "$((0x7255))|$((0x5293))|$((0x39393939))")
if [ -n "$Match" ]; then
	pids=$(echo $Match | grep -oP 'pid=\K\d+')
	check_pids=' '$pids
fi


Match=$(ss -apn | grep -E ":1 |:6 |:17 ")
if [ -n "$Match" ]; then
	pids=$(echo $Match | grep -oP 'pid=\K\d+')
	common_pid=$(echo "$pids" | sort | uniq -c | awk '$1 == 3 {print $2}')
	check_pids+=' '$common_pid
fi


sus_count1=0
mal_count1=0

if [ -n "$check_pids" ]; then
	for PID in $check_pids; do
		elf=$(ls -l /proc/$PID/exe | awk '{print $(NF)}')
		if [ -n "$elf" ]; then
			if [ "$elf" == "(deleted)" ]; then
				del_elf=$(ls -l /proc/$PID/exe | awk '{print $(NF-1)}')
				echo "[ Suspicious ] PID: "$PID "Process: "$del_elf
				let sus_count1=sus_count+1


			else
				check_elf=$(hexdump -ve '1/1 "%02x"' $elf | grep -o "c6459049c6459135c645922ac6459341c6459459c6459562" 2>/dev/null)
				if [ -n "$check_elf" ]; then
					echo "[ Malicious ] PID: "$PID "File: "$elf
					let mal_count1=mal_count1+1
				fi
			fi
		fi
	done
fi

if [ "$sus_count1" -eq 0 ] && [ "$mal_count1" -eq 0 ]; then
	echo " OK!!"
fi

echo -e "\n[ Stage 2 ] BPFDoor Controller Check"

mal_count2=0

Match=$(ps -ef | grep "abrtd" | grep -v "grep" | awk '{print $2}')
if [ -n "$Match" ]; then
        for PID in $Match; do
                elf=$(ls -l /proc/$PID/exe | awk '{print $NF}')
                check_elf=$(strings $elf | grep ":h:d:l:s:b:t")
		if [ -n "$check_elf" ]; then
			echo "[ Malicious ] PID: "$PID "File: "$elf
			let mal_count2=mal_count2+1
		fi
        done

fi

if [ "$mal_count2" -eq 0 ]; then
	echo " OK!!"
fi

echo -e "\n[ Stage 3 ] BPFDoor Variant Check"

mal_count3=0

Match=$(ps -ef | grep -E "sgaSolAgent|cmathreshd|udevd" | grep -v "grep" | awk '{print $2}')
if [ -n "$Match" ]; then
        for PID in $Match; do
                elf=$(ls -l /proc/$PID/exe | awk '{print $NF}')
                check_elf=$(grep "ttcompat" $elf && grep "127.0.0.1" $elf)
                if [ -n "$check_elf" ]; then
			echo "[ Malicious ] PID: "$PID "File: "$elf
			let mal_count3=mal_count3+1
                fi
        done

fi

if [ "$mal_count3" -eq 0 ]; then
	echo " OK!!"
fi

echo -e "\n******* [ Total Result ] ********"
let sus_total=sus_count1
let mal_total=mal_count1+mal_count2+mal_count3
echo " - Total Suspicious:"$sus_total
echo " - Total Malicious:"$mal_total
echo "------------------------------------------------------------------ "
echo "[ Scan Finish ]"
echo -e "\n"