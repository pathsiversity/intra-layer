#!/bin/bash

# Default plot variables

declare xLABEL=""
declare yLABEL=""
declare gTITLE=""
declare xRANGE=""
declare yRANGE=""
declare yTICS=""
declare xTICS=""
declare xCOL=""
declare yCOL=""


#PATH OF PCAP FILES
declare sPATH=/vagrant/EXP01
declare gPATH=/vagrant/PLOTS
declare pPATH=/vagrant/PDFS
declare vPATH=/vagrant


declare -a simType=(
                        "--shared" #Subflows compartilham o gargalo com c2
                        "--noshared" # Subflows não passam pelo gargalo
                        #"--bottleneck" # Subflows compartilham entre si o gargalo
                    )
declare -a simName=(
                        "-shared"
                        "-noshared"
                        #"-bottleneck"
                    )
declare -a sourceIps=(
						"192.1.1.2"
						"192.2.1.2"
						#"192.1.10.2"
						#"192.2.10.2"
	)
declare -a sourceNames=(
						"a2b"
						"c2d"
						#"e2f"
						#"g2h"
	)
declare -a dstIps=(
						"192.3.1.2"
						"192.4.2.2"
						#"192.3.10.2"
						#"192.4.20.2"
	)
declare -a dstNames=(
						"b2a"
						"d2c"
						#"f2e"
						#"h2g"
	)

declare MPTCP="--mptcp"
declare protocol="-mptcp"

#declare MPTCP="--tcp"
#declare protocol="-tcp"

# Terminal colors
source $vPATH/header.sh

AnalysisRTT(){
	
	cd ${sPATH}
	
	PCAP=$1
	TMPFILE='file.tmp'
	TMPDATA='data.tmp'

	#Get only file name, removed extension
	NAME_PREFIX="${PCAP%.*}"

	TSHARK_PAR="-Tfields -E header=y "
	TSHARK_PAR+="-e frame.number "
	TSHARK_PAR+="-e frame.time_relative "
	TSHARK_PAR+="-e ip.src -e ip.dst "
	TSHARK_PAR+="-e tcp.flags "
	TSHARK_PAR+="-e tcp.analysis.acks_frame -e tcp.analysis.ack_rtt "

	echo -e "${BLUE} Extract RTT Data${GRAY}"
	tshark $TSHARK_PAR -r $PCAP > $TMPFILE


	#cat $TMPFILE | gawk '$5=='16' && $7 {printf "%s %s %d %s\n",$3,$4, $2, $7}' > $TMPDATA
	cat $TMPFILE | gawk '$5=='16' && $7 {printf "%08.2f %0.6f %s \n",$2, $7, $4}' > $TMPDATA

	for (( ipi=0; ipi<${#sourceIps[@]}; ++ipi ))
    do
    	echo -e "Separing plot file: rtt-$NAME_PREFIX-${sourceNames[$ipi]}.plot"
    	cat $TMPDATA | grep ${sourceIps[$ipi]} > ${gPATH}/rtt-$NAME_PREFIX-${sourceNames[$ipi]}.plot
    done
    echo -e "${NOCOLOR}"

	Clean
	cd ${vPATH}
	echo -e "Done!"
}

AnalysisCWND(){
 #So an MSS of 1460 and a cwnd of 33 would be ~48k bytes. 
 #The cwnd at the beginning of a connection is usually 2, 3, or 10 
 #depending on the operating system and kernel version. 
 #The cwnd is initially increased by TCP Slow Start

 #CONGESTION WINDOW (cwnd):  A TCP state variable that limits the 
 #	  amount of data a TCP can send.  At any given time, a TCP MUST NOT
 #     send data with a sequence number higher than the sum of the
 #     highest acknowledged sequence number and the minimum of cwnd and
 #     rwnd.
 #'tcp.window_size_value'  is the value in the TCP header for window size
 #'tcp.window_size' is the Calculated size for the window if windows scaling is enabled

cd ${sPATH}

	PCAP=$1
	TMPFILE='file.tmp'
	TMPDATA='data.tmp'
	AWKC='$3 {printf("%08.2f \t \t %s \t %s\n", $1,$3,$2)}'

	#Get only file name, removed extension
	NAME_PREFIX="${PCAP%.*}"

	TSHARK_PAR="-Tfields -E header=n "
	TSHARK_PAR+="-e frame.time_relative "
	TSHARK_PAR+="-e ip.src "
	TSHARK_PAR+="-e tcp.window_size_value "

	echo -e "${BLUE}Extract CWND Data ${GRAY}"
	tshark $TSHARK_PAR -r $PCAP | awk "$AWKC" > $TMPFILE

	for (( ipi=0; ipi<${#sourceIps[@]}; ++ipi ))
    do
    	echo -e "Separing plot file: cwnd-$NAME_PREFIX-${sourceNames[$ipi]}.plot"
    	cat $TMPFILE | grep ${sourceIps[$ipi]} > ${gPATH}/cwnd-$NAME_PREFIX-${sourceNames[$ipi]}.plot
    done

	Clean
    cd ${vPATH}
    echo -e "${NOCOLOR}"
    echo -e "Done!"

}

AnalysisLosses(){
	# "tcp.analysis.lost_segment" is a message that tells you 
	#that Wireshark has seen a gap in the sequence numbers of a conversation.
	
	cd ${sPATH}

	PCAP=$1
	TMPFILE='file.tmp'
	TMPDATA='data.tmp'
	AWKC='$3 {printf("%08.2f \t \t %s \t %s\n", $1,$3,$2)}'

	NAME_PREFIX="${PCAP%.*}"

	TSHARK_PAR="-Tfields -E header=n "
	TSHARK_PAR+="-e frame.time_relative "
	TSHARK_PAR+="-e ip.src "
	TSHARK_PAR+="-e tcp.analysis.lost_segment "

	echo -e "${BLUE}Extract Losses Data ${GRAY}"
	tshark $TSHARK_PAR -r $PCAP | awk "$AWKC" > $TMPFILE

	for (( ipi=0; ipi<${#sourceIps[@]}; ++ipi ))
    do
    	echo -e "Separing plot file: lost-$NAME_PREFIX-${sourceNames[$ipi]}.plot"
    	#cat $TMPFILE | grep ${sourceIps[$ipi]} > loss-$NAME_PREFIX-${sourceNames[$ipi]}.plot
    	cat $TMPFILE | grep ${sourceIps[$ipi]} | uniq -c | awk '{print $2,$1}' > ${gPATH}/loss-$NAME_PREFIX-${sourceNames[$ipi]}.plot
    done

    Clean
    cd ${vPATH}
    echo -e "${NOCOLOR}"
    echo -e "Done!"
}

AnalysisDupACK(){
	
	cd ${sPATH}

	PCAP=$1
	TMPFILE='file.tmp'
	TMPDATA='data.tmp'
	AWKC='$3 {printf("%08.2f \t \t 1 \t %s\n", $1,$2)}'

	NAME_PREFIX="${PCAP%.*}"

	TSHARK_PAR="-Tfields -E header=n "
	TSHARK_PAR+="-e frame.time_relative "
	TSHARK_PAR+="-e ip.src "
	TSHARK_PAR+="-e tcp.analysis.duplicate_ack "

	echo -e "${BLUE}Extract DupACK Data ${GRAY}"
	tshark $TSHARK_PAR -r $PCAP | awk "$AWKC" > $TMPFILE

	for (( ipi=0; ipi<${#dstIps[@]}; ++ipi ))
    do
    	echo -e "Separing plot file: dupack-$NAME_PREFIX-${dstNames[$ipi]}.plot"
    	#cat $TMPFILE | grep ${dstIps[$ipi]} > dupack-$NAME_PREFIX-${dstNames[$ipi]}.plot
    	cat $TMPFILE | grep ${dstIps[$ipi]} | uniq -c | awk '{print $2,$1}' > ${gPATH}/dupack-$NAME_PREFIX-${dstNames[$ipi]}.plot
    done

    Clean
    cd ${vPATH}
    echo -e "${NOCOLOR}"
    echo -e "Done!"
}

AnalysisRetransmissions(){

	cd ${sPATH}

	PCAP=$1
	TMPFILE='file.tmp'
	TMPDATA='data.tmp'
	AWKC='$3 {printf("%08.2f \t \t %s \t %s\n", $1,$3,$2)}'

	NAME_PREFIX="${PCAP%.*}"

	TSHARK_PAR="-Tfields -E header=n "
	TSHARK_PAR+="-e frame.time_relative "
	TSHARK_PAR+="-e ip.src "
	TSHARK_PAR+="-e tcp.analysis.retransmission "

	echo -e "${BLUE}Extract Retransmissions ${GRAY}"
	tshark $TSHARK_PAR -r $PCAP | awk "$AWKC" > $TMPFILE

	for (( ipi=0; ipi<${#sourceIps[@]}; ++ipi ))
    do
    	echo -e "Separing plot file: ret-$NAME_PREFIX-${sourceNames[$ipi]}.plot"
    	#cat $TMPFILE | grep ${sourceIps[$ipi]} > ret-$NAME_PREFIX-${sourceNames[$ipi]}.plot
    	## To group results use uniq -c
    	cat $TMPFILE | grep ${sourceIps[$ipi]} | uniq -c | awk '{print $2,$1}' > ${gPATH}/ret-$NAME_PREFIX-${sourceNames[$ipi]}.plot
    done

    Clean
    cd ${vPATH}
    echo -e "${NOCOLOR}"
    echo -e "Done!"
}

AnalysisThroughput(){
	# The throughput itself corresponds to the quantity of data sent back and forth. 
	# Counting the bytes sent from the client to the server and 
	# vice versa is enough to evaluate the throughput.
	# Transmission time (in seconds) = Size of file (in bits) / Bandwidth (in bits/second) 
	# Throughput: Throughput (in bits) = Size of file (in bits) / Transmission time (in seconds

	cd ${sPATH}

	PCAP=$1

	NAME_PREFIX="${PCAP%.*}"

	AWKC='{printf "%.3f %07.4f\n", ($1-YODA),$2/1024/1024}'

	TMPFILE='file.tmp'
	TMPDATA='data.tmp'
	
	echo -e "${BLUE}Extract Throughput ${GRAY}"
	
	tcptrace -T -A1 $PCAP 1> /dev/null
	
	for lf in ${sourceNames[*]}
	do
    	XPLS=(`ls $lf*.xpl`)
   	 	cat $XPLS | grep dot | awk '{print $2,$3}' > $TMPFILE
   	 	echo -e "Separing plot file: $XPLS (${lf})"
		LUKE=$(head -n 1 $TMPFILE)
		cat $TMPFILE | awk -v YODA="$LUKE" "$AWKC" > ${gPATH}/tput-$NAME_PREFIX-${lf}.plot
	done

	Clean
	cd ${vPATH}
    echo -e "${NOCOLOR}"
    echo -e "Done!"

}


CalculateSRTT_RTO(){

	# Packet Size (1428)
	# RTT
	# CWND
	# PKTSIZE 
	# TPi
	
	PCAP=$1
	PCAPN="${PCAP#*/}" 		# remove dir
	
	NAME_PREFIX="${PCAP%.*}"

	TMPFILE="$NAME_PREFIX}.tmp"
	TMPDATA="rtt.tmp"

	TSHARK_PAR="-Tfields "
	TSHARK_PAR+="-e frame.number "
	TSHARK_PAR+="-e frame.time_relative "
	TSHARK_PAR+="-e ip.src "
	TSHARK_PAR+="-e tcp.analysis.ack_rtt "
	TSHARK_PAR+="-e tcp.window_size_value "
	TSHARK_PAR+="-e tcp.len  "

	
	tshark $TSHARK_PAR -r $tPATH/$PCAPN > $TMPFILE

	for (( ipi=0; ipi<${#dstIps[@]}; ++ipi ))
    do
    	echo -e "${BLUE}\t Extracting ${dstIps[$ipi]} Data ${GRAY}"
    	#pegar o arquivo do RTT 
    	AWKC='NF>5 && $3=="'${dstIps[$ipi]}'" {print $2,$4} NF==5 && $3=="'${srcIps[$ipi]}'"{print $2,$4,$5}'
    	cat $TMPFILE | awk "$AWKC" > $TMPDATA

    	awk 'BEGIN{ 
					SRTT=0;
					RTTVAR=0;
					RTO=0;
					G=4;
					RTT=0;
					K=4;
					alpha=1/8;
					beta=1/4;
					PKTSIZE=1492;
					LR=0.001
					CWND=0
			} 
			NR==1 && NF==2{
				RTT=$2;
				SRTT=RTT;
				RTTVAR=RTT/2;
				if(G>(K*RTTVAR)){
					RTO=SRTT+G;
				}else{
					RTO=SRTT+K*RTTVAR;
				}
			}
			NR>1 && NF==3{
				CWND=$2
				PKTSIZE=$3
			}
			NR>1 && NF==2{
				RTT=$2;
				ABS= (SRTT - R) >= 0 ? (SRTT - R) : -(SRTT - R);
				RTTVAR=(1 - beta) * RTTVAR + beta * ABS;
				SRTT=(1 - alpha) * SRTT + alpha * RTT;
				if(G>(K*RTTVAR)){
					RTO=SRTT+G;
				}else{
					RTO=SRTT+K*RTTVAR;
				}
			}
			{
				if(PKTSIZE>0 && SRTT>0){
					TPi=(CWND * PKTSIZE)/SRTT
					printf "%0.2f \t %0.6f \t %0.3f  \t %0.3f \t %0.3f \n",$1,SRTT,RTO, CWND,TPi
				}
			}
		' $TMPDATA > ${srcNames[$ipi]}.part
    done
}


PlotLines(){

	# Need install texlive-font-utils gnuplot5 gawk

	F_PREFIX=$1

	cd ${gPATH}

	PLOT_FILES=(`ls ${gPATH}/ | grep .plot| grep ${F_PREFIX}`)

	gnucmd=`echo "
	########################### BEGIN ####################################
	reset
	#formato de codificação
	set termoption dashed
	set encoding utf8

	#formato do arquivo, estilo da fonte e tamanho da fonte
	set terminal postscript eps enhanced  color 'Helvetica, 28'

	#arquivo de saída em formato pdf
	set output '| epstopdf --filter > ${pPATH}/${F_PREFIX}.pdf'

	set title '$gTITLE' font 'Helvetica,22'
	set xlabel 'Experiment Time (s)' font 'Helvetica,22'
	set ylabel '$yLABEL' font 'Helvetica,22'
	set format x '%.0f'
	set format y '%.2f'
	#set xdata time

	#set yrange ${yRANGE}
	set xrange [0:65]

	set ytics font 'Helvetica,16'
	set xtics font 'Helvetica,16'

	#set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 pi -1 ps 1.5
	#set pointintervalbox 3

	#cria estilo para a caixa e os pontos
	set style line 1 lc rgb '#00f9ff' lt 1 dashtype 1 lw 1 pt 64
	set style line 2 lc rgb '#d600ff' lt 1 dashtype 1 lw 1 pt 66
	set style line 3 lc rgb '#f0ff00' lt 1 dashtype 1 lw 1 pt 65
	set style line 4 lc rgb '#00FF00' lt 1 dashtype 1 lw 1 pt 68
	set style line 5 lc rgb '#000000' lt 1 dashtype '-' lw 0.1
	set pointsize 1

	#posição da legenda
	set key outside
	set key horiz
	set key center bottom samplen 4 font 'Helvetica,14' reverse Left

	#cria a grade
	set grid ytics ls 5
	set grid xtics ls 5
	" `

	gnucmd+="plot "

	for (( fe=0; fe<${#PLOT_FILES[@]}; ++fe )) 
	do
		if [[ -s "${PLOT_FILES[$fe]}" ]] 
		then
			index=$(($fe + 1))
			SUBFLOW=`echo ${PLOT_FILES[$fe]} | rev | cut -c1-8 | rev | cut -d'.' -f1`
			gnucmd+="'${PLOT_FILES[$fe]}' using 1:2 t 'Path $SUBFLOW' with points ls $index , "
			#cp ${PLOT_FILES[$fe]} ${gPATH}
		fi
	done
	# Save Plots to Future Replot
	#echo -e "$gnucmd" > ${gPATH}/${F_PREFIX}.gpl
	echo -e "$gnucmd" | gnuplot

	cd ${vPATH}

}
# Function to plot all files in ${sPath}
PlotBacth(){

	#get name_prefix of plot files from work dir
	PLOT_PREFIX=(`ls ${gPATH} | grep plot | rev| cut -c10- | rev | uniq`)


	# for each file, verify the number of plot files (expect 4)
	for (( filep=0; filep<${#PLOT_PREFIX[@]}; ++filep ))
	do
		NUM_LINES=`ls ${gPATH}/ | grep .plot| grep ${PLOT_PREFIX[$filep]} | wc -l`
		PREFIX=`ls ${gPATH}/ | grep .plot| grep ${PLOT_PREFIX[$filep]} | cut -d'-' -f1| uniq`
		echo -e "${MAGENTA} Plot ${PLOT_PREFIX[$filep]} with $NUM_LINES lines"
		gTITLE="Plot `echo $PREFIX | awk '{print toupper($0)}'`"
		yLABEL="`echo $PREFIX | awk '{print toupper($0)}'`"
		PlotLines ${PLOT_PREFIX[$filep]}
	done
	echo -e "${NOCOLOR}"
}

Plot(){

	PlotBacth
}

Analysis(){
	# List ALL PCAP-FILES

	cd ${gPATH}
	Clean plot
	Clean xpl 
	cd ${gPATH}


	PCAPS=(`ls ${sPATH} | grep pcap | grep c1`)
	echo -e "${RED}==> Analysis of ${#PCAPS[@]} pcaps <==${NOCOLOR}"
	for (( filep=0; filep<${#PCAPS[@]}; ++filep ))
	do
				
		
		echo ${PCAPS[$filep]}
		AnalysisRTT ${PCAPS[$filep]}
		#AnalysisCWND ${PCAPS[$filep]}
		#AnalysisLosses ${PCAPS[$filep]}
		#AnalysisDupACK ${PCAPS[$filep]}
		##AnalysisRetransmissions ${PCAPS[$filep]}
		#AnalysisThroughput ${PCAPS[$filep]}

	done

	Plot
}

Clean(){

    if [ "$1" == "" ]; then
        Clean "tmp"
    else
        count=`find ./ -maxdepth 1 -name "*.${1}" | wc -l`
        if [ ${count} != 0 ]; then
            rm *.${1}
            echo "Removed ${count} .${1} files"
        fi
    fi

}

ShowUsage()
{
    echo -e "${GRAY}\n"
    echo "Script to run Mininet MPTCP Script"
    echo "Usage: ./run-experiments.sh <COMMAND> [PARAM]"
    echo "Option: -a <pcap> to generate data files"
    echo -e "${WHITE}\n"
}

main()
{
     Analysis
}

main "$@"