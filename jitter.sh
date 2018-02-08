#!/bin/bash
lc_all=C


declare -a srcIps=(
						"192.1.1.2"
						"192.2.1.2"
						#"192.1.10.2"
						#"192.2.10.2"
)

declare -a dstIps=(
						"192.3.1.2"
						"192.4.2.2"
						#"192.3.10.2"
						#"192.4.20.2"
)

declare -a srcNames=(
						"a2b"
						"c2d"
						#"e2f"
						#"g2h"
)

declare -a dstNames=(
						"b2a"
						"d2c"
						#"f2e"
						#"h2g"
)

declare sPATH=/vagrant/TMP # work dir
declare vPATH=/vagrant	# home experiments dir
declare tPATH=/vagrant/EXP01 # traces dir



RunBatch(){

	# List ALL PCAP-FILES
	PCAPs_src=(`ls ${sPATH} | grep pcap | grep c1`)
	PCAPs_dst=(`ls ${sPATH} | grep pcap | grep s1`)
	
	for (( pcap=0; pcap<${#PCAPS[@]}; ++pcap ))
	do
		echo -e "${RED}==> Analysis $pcap of ${#PCAPS[@]} pcaps <==${NOCOLOR}"
		Execute ${PCAPs_src[$pcap]} ${PCAPs_src[$pcap]}
	done
}



Execute(){

PLOT_ARRAY=()
#ARRAY+=('foo')

#PCAPf=$1
PCAPs=$1
PCAPr=$2
# Eu poderia retirar o fluxo do arquivo, mas estava tando trabalho!
for (( IDX=0; IDX<${#srcIps[@]}; ++IDX ))
do
    echo "=======> $PCAPs ${srcIps[$IDX]} --> ${dstIps[$IDX]}"
    #Jitter $PCAPs $IDX
    Latency $PCAPs $PCAPr $IDX
    #OneWayDelayForward $PCAPs $PCAPr $IDX
    #OneWayDelayBackWard $PCAPs $PCAPr $IDX
    #echo $PLOT
done

}


Jitter(){

	cd ${sPATH}
	
	PCAP=$1
	IDX=$2
	
	# from dir/filename
	PCAPf="${PCAP#*/}" # remove dir
	PCAPn="${PCAPf%.*}"  # remove extension
	#echo "${PCAPfn%/*}" # remove filename

	echo $PCAPf
	echo $PCAPn

	SRC=${srcIps[$IDX]}
	DST=${dstIps[$IDX]}



	OUT="jtt-$PCAPn-${srcNames[$IDX]}.dat"

	sPCAP="stream_${srcNames[$IDX]}.cap.tmp"
	dPCAP="stream_${dstNames[$IDX]}.cap.tmp"

	#tshark -nr ${tPATH}/$PCAPf -Y "(ip.src eq ${SRC} and ip.dst eq ${DST} )" -w $sPCAP
	#tshark -nr ${tPATH}/$PCAPf -Y "(ip.src eq ${DST} and ip.dst eq ${SRC} )" -w $dPCAP

	#tshark -r $sPCAP -T fields -e frame.time_epoch > frameS.tmp
	#tshark -r $dPCAP -T fields -e frame.time_epoch > frameD.tmp

	#tshark -r $sPCAP | awk '{print $2}' > ticks.tmp
	#tshark -r $sPCAP -T fields -e tcp.len > rates.tmp


	declare -a S=(`cat frameS.tmp`)
	declare -a R=(`cat frameD.tmp`)
	declare -a T=(`cat ticks.tmp`)
	declare -a Rate=(`cat rates.tmp`)
	jitter=0
	i=0


	j=`echo ${#S[@]}`
	let j=$j-2

	echo "" > $OUT
	#for ((k=0; k<=$j; k++)); do
	for j in "${!T[@]}"; do

	 	D=`echo "(${R[i+1]} - ${R[$i]}) - (${S[i+1]} - ${S[$i]})" |bc |tr -d -`
	 	
	 	base=`echo "(${S[i+1]} - ${S[$i]})" |bc |tr -d -`
	 	cond=`echo "$base>0" | bc`
	 	
	 	if [ ${cond} == 0 ] 
	 	then
      		#echo "DIVIDE BY 0 ${1}"
      		break
      	else
		 	rate=`echo "((${Rate[$i]}*8) / (${S[i+1]} - ${S[$i]}))" |bc |tr -d -`
		 	jitter=`echo "$jitter + ($D - $jitter)/16" |bc -l`
		 	printf "%.4f  %.4f \n" ${T[$i]} $jitter >> $OUT
		 	#echo "${T[$i]} $jitter $rate" #>> $OUT
		 	i=$((i+1))
	 	fi

	done
	
	#rm ${sPATH}/*.tmp 

	cd ${vPATH}
	
	#echo "PLOT GRAPH from $OUT"
	PlotGraph $OUT
	exit 0
	echo "$OUT"
}

PlotGraph(){

	DATASET=$1

	OUT="${DATASET%.*}"

	cmd=`echo "
		#formato do arquivo, estilo da fonte e tamanho da fonte
		set terminal postscript eps enhanced color 'Helvetica, 28'

		#arquivo de saída em formato pdf
		set output '| epstopdf --filter > ${sPATH}/${OUT}.pdf'

		set style data points
		set nogrid

		set style line 1 lt 1 lw 2
		set style line 2 lt 2 lw 2
		set style line 3 lt 3 lw 5
		set style line 4 lt 3 lw 1
		set style line 5 lt 3 lw 2
		set style line 6 lt 3 lw 1
		set style line 7 lt 17 lw 2
		set style line 8 lt 17 lw 4

		set xlabel 'Time (sec)'
		set ylabel 'Jitter (sec)'
		#("'$2'"/1)

	"`
	cmd+="plot '${sPATH}/$DATASET' using 1:2 title 'jitter' with linespoints ls 1"

	#replot >> jitter.gp

	echo -e "$cmd" | gnuplot

}

Latency(){

	cd ${sPATH}
	
	pcap_src=$1 # source PCAP
	pcap_dst=$2 # receiver PCAP
	IDX=$3
	
	# from dir/filename
	PCAPsrc_file="${pcap_src#*/}"   # remove dir
	PCAPsrc_name="${PCAPsrc_file%.*}"   # remove extension
	
	# from dir/filename
	PCAPdst_file="${pcap_dst#*/}"   # remove dir
	PCAPdst_name="${PCAPdst_file%.*}"  # remove extension

	ipSRC=${srcIps[$IDX]}

	OUT_file="latency-$PCAPsrc_name-${srcNames[$IDX]}.dat"

	TMPsrc="stream_${srcNames[$IDX]}.tmp"
	TMPdst="stream_${dstNames[$IDX]}.tmp"

	#tshark -Y "(ip.src eq 192.1.1.2 )" -T fields -e frame.time_epoch -e tcp.options.mptcp.dataseqno -nr 

	TSHARK_PAR="-Tfields "
	TSHARK_PAR+="-e frame.time_epoch "
	TSHARK_PAR+="-e tcp.options.mptcp.dataseqno "

	tshark -Y "(ip.src eq ${ipSRC} )" $TSHARK_PAR -nr ${tPATH}/$PCAPsrc_file > $TMPsrc
	tshark -Y "(ip.src eq ${ipSRC} )" $TSHARK_PAR -nr ${tPATH}/$PCAPdst_file > $TMPdst
	tshark -Y "(ip.src eq ${ipSRC} )" -nr ${tPATH}/$PCAPsrc_file | awk '{print $2}' > ticks.tmp
	
	cat $TMPsrc | awk '{print $1}' > frame1.tmp
	cat $TMPsrc | awk '{print $2}' > seqno1.tmp

	cat $TMPdst | awk '{print $1}' > frame2.tmp
	cat $TMPdst | awk '{print $2}' > seqno2.tmp

	declare -a array1=(`cat seqno1.tmp`)
	declare -a array2=(`cat seqno2.tmp`)
	declare -a frame1=(`cat frame1.tmp`)
	declare -a frame2=(`cat frame2.tmp`)
	declare -a T=(`cat ticks.tmp`)
	
	latency=0
	i=0

	echo "" > $OUT_file

	echo "Array 1: ${#array1[@]}"
	echo "Array 1: ${#array2[@]}"
	echo "Frame 1: ${#frame1[@]}"
	echo "Frame 1: ${#frame2[@]}"

	for i in "${!array1[@]}"; do
		value1=${array1[$i]}
		#echo -e "[$i]=$value1"
		#clear
		#printf "%s of %s \n" "$i" "${#array1[@]}"
				
		for j in "${!array2[@]}"; do
			if [ "$value1" = "${array2[$j]}" ]; then
				#echo -e "\t [$j]=${array2[$j]}"
				latency=`echo "(${frame2[$j]} - ${frame1[$i]})*1000" |bc -l`
				#echo "LATENCY[${frame2[$j]}-${frame1[$i]}=$latency]"
				
				if (( $(echo "$latency > 0" |bc -l) )); then
					echo "${T[$i]} $latency" >> $OUT_file
				fi
				
	        	#else
				unset array1[$i]
				unset array2[$j]
				break
			fi
		 done
	done

	cd ${vPATH}

	PlotGraph $OUT_file

}

OneWayDelayForward(){

	cd ${sPATH}
	

	echo "**** OneWayDelayForward ****"

	pcap_src=$1 # source PCAP
	pcap_dst=$2 # receiver PCAP
	IDX=$3
	
	# from dir/filename
	PCAPsrc_file="${pcap_src#*/}"   # remove dir
	PCAPsrc_name="${PCAPsrc_file%.*}"   # remove extension
	
	# from dir/filename
	PCAPdst_file="${pcap_dst#*/}"   # remove dir
	PCAPdst_name="${PCAPdst_file%.*}"  # remove extension

	ipSRC=${srcIps[$IDX]}
	ipDST=${dstIps[$IDX]}

	OUT_file="owdf-$PCAPsrc_name-${srcNames[$IDX]}-${dstNames[$IDX]}.dat"

	TMPsrc="stream_${srcNames[$IDX]}.tmp"
	TMPdst="stream_${dstNames[$IDX]}.tmp"
	# tcpdump 'src 192.1.1.2 and dst 192.3.1.2 and' 'tcp[13] & 8!=0' -Snnr EXP01/dump-1-bottleneck-mptcp-c1-all.pcap -c 100
	#tshark -Y "(ip.src eq 192.1.1.2 )" -T fields -e frame.time_epoch -e tcp.options.mptcp.dataseqno -nr 

	TSHARK_SEQ="-Tfields "
	TSHARK_SEQ+="-e frame.time_epoch "
	TSHARK_SEQ+="-e tcp.options.mptcp.dataseqno "

	## OWD_f
	tshark -Y "(ip.src eq ${ipSRC} )" $TSHARK_SEQ -nr ${tPATH}/$PCAPsrc_file > $TMPsrc
	tshark -Y "(ip.src eq ${ipSRC} )" $TSHARK_SEQ -nr ${tPATH}/$PCAPdst_file > $TMPdst
	tshark -Y "(ip.src eq ${ipSRC} )" -nr ${tPATH}/$PCAPsrc_file | awk '$2 {print $2}' > ticks.tmp

	cat $TMPsrc | awk '$1 {print $1}' > frame1.tmp
	cat $TMPsrc | awk '$2 {print $2}' > seqno1.tmp

	cat $TMPdst | awk '$1 {print $1}' > frame2.tmp
	cat $TMPdst | awk '$2 {print $2}' > seqno2.tmp

	Match $OUT_file

}

OneWayDelayBackWard(){

	cd ${sPATH}

	echo "**** OneWayDelayBackWard ****"
	
	pcap_src=$1 # source PCAP
	pcap_dst=$2 # receiver PCAP
	IDX=$3
	
	# from dir/filename
	PCAPsrc_file="${pcap_src#*/}"   # remove dir
	PCAPsrc_name="${PCAPsrc_file%.*}"   # remove extension
	
	# from dir/filename
	PCAPdst_file="${pcap_dst#*/}"   # remove dir
	PCAPdst_name="${PCAPdst_file%.*}"  # remove extension

	ipA=${srcIps[$IDX]}
	ipB=${dstIps[$IDX]}

	OUT_file="owdb-$PCAPsrc_name-${srcNames[$IDX]}-${dstNames[$IDX]}.dat"

	TMPsrc="stream_${srcNames[$IDX]}.tmp"
	TMPdst="stream_${dstNames[$IDX]}.tmp"
	
	TSHARK_ACK="-Tfields "
	TSHARK_ACK+="-e frame.time_epoch "
	TSHARK_ACK+="-e tcp.options.mptcp.dataack "

	#OWD_b. dst ip its the source of acks
	tshark -Y "(ip.src eq ${ipB} )" $TSHARK_ACK -nr ${tPATH}/$PCAPsrc_file > $TMPsrc
	tshark -Y "(ip.src eq ${ipB} )" $TSHARK_ACK -nr ${tPATH}/$PCAPdst_file > $TMPdst
	tshark -Y "(ip.src eq ${ipB} )" -nr ${tPATH}/$PCAPdst_file | awk '$2 {print $2}' > ticks.tmp

	cat $TMPsrc | awk '$1 {print $1}' > frame1.tmp
	cat $TMPsrc | awk '$2 {print $2}' > seqno1.tmp

	cat $TMPdst | awk '$1 {print $1}' > frame2.tmp
	cat $TMPdst | awk '$2 {print $2}' > seqno2.tmp

	Match $OUT_file

}
# real	0m8.995s
Match(){

	cd ${sPATH}
	
	OUT=$1

	echo `date -d`
	declare -a array1=(`cat seqno1.tmp | awk '$1 {print $0}' | head -n 1000`)
	declare -a array2=(`cat seqno2.tmp | awk '$1 {print $0}' | head -n 1000`)
	declare -a frame1=(`cat frame1.tmp | awk '$1 {print $0}' | head -n 1000`)
	declare -a frame2=(`cat frame2.tmp | awk '$1 {print $0}' | head -n 1000`)
	declare -a T=(`cat ticks.tmp | awk '$1 {print $0}' | head -n 1000`)
	
	latency=0
	i=0
 
	echo "" > $OUT

	echo "Array 1: ${#array1[@]}"
	echo "Array 2: ${#array2[@]}"
	echo "Frame 1: ${#frame1[@]}"
	echo "Frame 2: ${#frame2[@]}"

	for i in "${!array1[@]}"; do
		value1=${array1[$i]}
		#echo -e "[$i]=$value1"
		
		#printf "[%s]--" "$i"	
		for j in "${!array2[@]}"; do
			if [ "$value1" = "${array2[$j]}" ]; then
				#printf "[%s]=%s\n" "$j" "${array2[$j]}"
				
				latency=`echo "(${frame1[$i]}-${frame2[$j]})*1000" |bc -l`
				#echo "LATENCY[${frame1[$i]}-${frame2[$j]}=$latency]"
				
				if (( $(echo "$latency > 0" |bc -l) )); then
					echo -e "${T[$i]} \t $latency \t ${frame1[$i]} \t ${frame2[$j]} " >> $OUT
				fi
				unset array2[$j]
				unset frame1[$i]
				unset frame2[$j]
				unset T[$i]
				break
			fi
		done
	done
	echo "FISISH"

	cd ${vPATH}

	#PlotGraph $OUT

}


ShowUsage()
{
    echo "Usage: ./script.sh <COMMAND> [PARAM]"
}

main()
{
    case "$1" in
        '-r'|'--run' )
            #echo 'DISABLED!'
            #exit 0
            Execute $2 $3
           
        ;;

        '-p'|'--plot' )
			
			echo "PLOT"
            PlotGraph $2
            
        ;;

        '-m'|'--match' )
			
			echo "Matching"
            Match $2
            
        ;;

        *)
            ShowUsage
            exit 1
        ;;
    esac

    exit 0
}

main "$@"
