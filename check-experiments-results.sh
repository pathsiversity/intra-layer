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
                        #"--noshared" # Subflows não passam pelo gargalo
                        #"--bottleneck" # Subflows compartilham entre si o gargalo
                    )
declare -a simName=(
                        "-shared"
                        #"-noshared"
                        #"-bottleneck"
                    )
declare -a sourceIps=(
						"192.1.1.2"
						#"192.2.1.2"
						"192.1.10.2"
						"192.2.10.2"
	)
declare -a sourceNames=(
						"a2b"
						#"c2d"
						"e2f"
						"g2h"
	)

declare -a srcAllNames=(
						"a2b"
						"c2d"
						"e2f"
						"g2h"
	)
declare -a dstIps=(
						"192.3.1.2"
						#"192.4.2.2"
						"192.3.10.2"
						"192.4.20.2"
	)
declare -a dstNames=(
						"b2a"
						#"d2c"
						"f2e"
						"h2g"
	)

declare -a pathNames=(
	"A"
	#"B"
	"B"
	"C"
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

	AWKC='{printf "%.3f %07.4f\n", ($1-YODA),$2}'

	TMPFILE='file.tmp'
	TMPDATA='data.tmp'
	
	echo -e "${BLUE} Extract Throughput ${GRAY}"
	#tcptrace -T -A1 $PCAP 1> /dev/null

	for lf in ${srcAllNames[*]}
	do
    	XPLS="${lf}_tput.xpl"

    	if [ -s "$XPLS" ] 
		then
			xpl2gpl $XPLS
   	 		cat $lf*.datasets | awk 'BEGIN{c=1}{if(!$2) c=0} {if(c) print $0}' > ${gPATH}/tput-$NAME_PREFIX-${lf}.plot
		fi

   	 	#cat $XPLS | grep dot | awk 'NF==3 {print $2,$3}' > $TMPFILE

   	 	
   	 	#echo -e "Separing plot file: $XPLS (${lf})"
		#LUKE=`head -n 1 $TMPFILE | awk '{print $1}'`
		#cat $TMPFILE | awk -v YODA="$LUKE" "$AWKC" > ${gPATH}/tput-$NAME_PREFIX-${lf}.plot
		
	done
	
	Clean

	cd ${vPATH}
    echo -e "${NOCOLOR}"
    echo -e "Done!"

    exit 0

}


AnalysisSequenceNumber(){

	cd ${sPATH}
	
	PCAP=$1
	PCAPN="${PCAP#*/}" 		# remove dir

	NAME_PREFIX="${PCAP%.*}"
	OUT_PREFIX="${PCAP%.*}.txt"

	TMPFILE="allsources.tmp"
	TMPFILE_SQ="fromsrc.tmp"
	SAIDA_A="saida.tmp"
	TMPRTT="thp.tmp"
	VALUES="values.tmp"
	TMP_UNIQ="uniqip.tmp"

	TSHARK_PAR="-Tfields "
	TSHARK_PAR+="-e ip.src "
	TSHARK_PAR+="-Tfields "
	TSHARK_PAR+="-e frame.time_relative "
	TSHARK_PAR+="-e tcp.options.mptcp.dataseqno "

	echo -e "${BLUE} Extract PCAP ${GRAY}"
	tshark $TSHARK_PAR -r $sPATH/$PCAPN > $TMPFILE

	echo "" > $TMPFILE_SQ

	for (( ipi=0; ipi<${#sourceIps[@]}; ++ipi ))
    do
    	cat $TMPFILE | awk '$1=="'${sourceIps[$ipi]}'" && NF==3 {print $0}' >> $TMPFILE_SQ
    done

	# Extract only DSN
	echo -e "${BLUE} Extract DSN ${GRAY}"
	awk '$3 {print $3}' $TMPFILE_SQ > $TMPRTT
	
	# Count Repeated Values
	echo -e "${BLUE} SORT DSN and UNIQ ${GRAY}"
	cat $TMPRTT | sort | uniq -c | awk '$1>1 {print $0}' > $VALUES

	TOTAL=`wc -l $TMPRTT | awk '{print $1}'`
	#LDUPS=`wc -l $VALUES | awk '{print $1}'` 
	TDUPS=`awk 'BEGIN{count=0}{count+=$1}END{print count}' $VALUES`


	#echo "TOTAL: $TOTAL"
	#echo "LINES: $LDUPS"
	#echo "TDUPS: $TDUPS"

	echo -e "${BLUE} MATH REPEATED DSN ${GRAY}"
	awk 'BEGIN{
		while(getline < "'$VALUES'"){
			DSN[$2]=$1
		}
	}
	{
		if(DSN[$3]){
			printf "%s \t %s \t %s \t %s\n",$2,$1,$3,DSN[$3]
		}
	}
	' $TMPFILE > $TMP_UNIQ

	# Ate aqui tenho uma lista dos DSN repetidos
	# E tambem, os respectivos IPS

	LINE_OUT="$TOTAL $TDUPS"

	# Tento contar os DSN por IP e verificar se tem repetidos
	for (( ipi=0; ipi<${#sourceIps[@]}; ++ipi ))
    do
    	cat $TMP_UNIQ | awk '$2=="'${sourceIps[$ipi]}'" {printf "%.2f \t %s \t %s \n", $1, $3, $4}' > ${sourceNames[$ipi]}
    	cat ${sourceNames[$ipi]} | awk '{print $2}' | sort | uniq -c > ${sourceNames[$ipi]}.tmp

    	#wc -l ${sourceNames[$ipi]} | awk '{print $1}'

    	awk 'BEGIN{
    		ct=0;
			while(getline < "'${sourceNames[$ipi]}.tmp'"){
				DSN[$2]=$1
			}
		}
		{
			if(DSN[$2]){
				ct+=DSN[$2]
				#printf "%s \t %s \t %s \t %s \t %.2f\n",$1,$2,$3,DSN[$2],ct
			}
		}END{
			printf "%.0f\n",NR
		}
		' ${sourceNames[$ipi]} > ${sourceNames[$ipi]}-uniq.tmp

		XTOT=`cat ${sourceNames[$ipi]}-uniq.tmp`

		LINE_OUT+=" $XTOT ${sourceNames[$ipi]}"

		echo -e "$XTOT ${sourceNames[$ipi]}"

		TOTDUPS=$((XTOT+TOTDUPS))
    	#LINESBY=`wc -l ${sourceNames[$ipi]} | awk '{print $1}'`
    	#cat ${sourceNames[$ipi]} | awk '{print $2}' | sort| uniq -c | awk 'BEGIN{ct=0;tot="'$LINESBY'"}{ct+=$1}END{print ct,tot}'
    done

    echo -e "$LINE_OUT" >> $SAIDA_A
    
}



AnalysisThroughput2(){

	# Packet Size (1428)
	# RTT
	# RTO
	# LR (unknown!)

	cd ${sPATH}
	
	PCAP=$1
	PCAPN="${PCAP#*/}" 		# remove dir

	NAME_PREFIX="${PCAP%.*}"

	TMPFILE="$NAME_PREFIX.tmp"
	TMPRTT="thp.tmp"

	TSHARK_PAR="-Tfields "
	TSHARK_PAR+="-e frame.number "
	TSHARK_PAR+="-e frame.time_relative "
	TSHARK_PAR+="-e ip.src "
	TSHARK_PAR+="-e tcp.analysis.ack_rtt "
	TSHARK_PAR+="-e tcp.window_size_value "
	TSHARK_PAR+="-e tcp.len  "

	echo -e "${BLUE} Extract Throughput ${GRAY}"
	tshark $TSHARK_PAR -r $sPATH/$PCAPN > $TMPFILE

	for (( ipi=0; ipi<${#dstIps[@]}; ++ipi ))
    do
    	cat $TMPFILE | grep ${dstIps[$ipi]} | awk 'NF>5 {print $2,$4}' > $TMPRTT

    	awk 'BEGIN{ 
					SRTT=0;
					RTTVAR=0;
					RTO=0;
					G=1;
					RTT=0;
					K=4;
					alpha=1/8;
					beta=1/4;
					PKTSIZE=1492;
					LR=0.001
			} 
			NR==1{
				RTT=$2;
				SRTT=RTT;
				RTTVAR=RTT/2;
				if(G > (K*RTTVAR)){
					RTO=SRTT+G;
				}else{
					RTO=SRTT+K*RTTVAR;
				}
			}
			NR>1{
				RTT=$2;
				ABS= (SRTT - R) >= 0 ? (SRTT - R) : -(SRTT - R);
				RTTVAR=(1 - beta) * RTTVAR + beta * ABS;
				SRTT=(1 - alpha) * SRTT + alpha * RTT;
				if(G > (K*RTTVAR)){
					RTO=SRTT+G;
				}else{
					RTO=SRTT+K*RTTVAR;
				}
				
				P1= (2*LR)/3
				P2= RTO * ((3 * LR)/8)^(1/3)
				P3= LR * (1 + 32 * (LR^2))

				TP=PKTSIZE/(SRTT * sqrt(P1 + P2 * P3))
				
				printf "%.2f \t %.3f \n",$1,(TP/1024/1024)
			}
		' $TMPRTT > ${gPATH}/tput-$NAME_PREFIX-${dstNames[$ipi]}.plot
	
    done
}


PlotFrequencies(){

	FF_FILE=$1
	F_PREFIX=${gPATH}/$FF_FILE

	cmdgnu=`echo "
	########################### BEGIN ####################################
	clear
	reset

	set key off
	set border 3

	#formato de codificação
	set termoption dashed
	set encoding utf8

	#formato do arquivo, estilo da fonte e tamanho da fonte
	set terminal postscript eps enhanced  color 'Helvetica, 28'

	#arquivo de saída em formato pdf
	set output '| epstopdf --filter > ${pPATH}/ff.pdf'

	# Add a vertical dotted line at x=0 to show centre (mean) of distribution.
	set yzeroaxis

	# Each bar is half the (visual) width of its x-range.
	set boxwidth 0.05 absolute
	set style fill solid 1.0 noborder

	bin_width=0.1
	bin_number(x)=floor(x/bin_width)
	rounded(x)=bin_width*(bin_number(x)+0.5)
	
	plot '$F_PREFIX' using (rounded("'$2'")):(2) smooth frequency with boxes
	########################### END ####################################
	" `	

	echo -e "$cmdgnu" | gnuplot 

	exit 0

}


PlotCDF(){

	F_PREFIX=$1
	FILETYPEX=$2
	PLOT_FILES=(`ls ${gPATH}/ | grep .plot| grep ${F_PREFIX%.*} | grep $FILETYPEX`)

	xLABEL=$FILETYPEX
	if [ "$FILETYPEX" = "tput" ];then
		xLABEL="Vazão (Mbps)"
	fi

	if [ "$FILETYPEX" = "rtt" ];then
		xLABEL="RTT (ms)"
	fi


	cd ${gPATH}

	gnucmd=`echo "
	########################### BEGIN ####################################
	reset
	#formato de codificação
	set termoption dashed
	set encoding utf8

	#formato do arquivo, estilo da fonte e tamanho da fonte
	set terminal postscript eps enhanced  color 'Helvetica, 36'

	#arquivo de saída em formato pdf
	set output '| epstopdf --filter > ${pPATH}/cdf-$FILETYPEX-${F_PREFIX}.pdf'

	set style line 1 lc rgb '#000000' lt 2 dashtype 3 lw 2 pt 64 ps 2 #pi -1
	set style line 2 lc rgb '#000000' lt 2 dashtype 4 lw 2 pt 65 ps 2 #pi -1
	set style line 3 lc rgb '#000000' lt 3 dashtype 5 lw 2 pt 66 ps 2 #pi -1
	set style line 4 lc rgb '#000000' lt 4 dashtype 6 lw 3 pt 68 ps 2 #pi -1
	set style line 5 lc rgb '#000000' lt 2 dashtype '-' lw 0.2
	set style line 6 lc rgb '#696969' lt 2 dashtype 2 lw 1
	
	set ytics font 'Helvetica,24' 0.0,0.20,1.0
	set xtics font 'Helvetica,24' #rotate by 45 right


	#set title 'CDF' font 'Helvetica,32'
	set xlabel '$xLABEL' font 'Helvetica,28'
	#set ylabel 'FDA' font 'Helvetica,32'

	set format y '%.1f'
	#set format x '%.1f'

	set yrange [0:1]
	set key right bottom samplen 4 font 'Helvetica,26' reverse Left

	set size square
	set grid ytics ls 5
	set grid xtics ls 5
	
	"`
	gnucmd+="plot "


	TMPFILE="file.tmp"
	index=0
	for (( fe=0; fe<${#PLOT_FILES[@]}; ++fe )) 
	do

		if [[ -s "${PLOT_FILES[$fe]}" ]] 
		then
			

			index=$(($fe + 1))
			TMPPLOT="cdf-$index-${PLOT_FILES[$fe]}.tmp"
			SUBFLOW=`echo ${PLOT_FILES[$fe]} | rev | cut -c1-8 | rev | cut -d'.' -f1`

			if [ "$SUBFLOW" = "a2b" ] || [ "$SUBFLOW" = "b2a" ];then
				SUBFLOW="A"
		    fi

		    if [ "$SUBFLOW" = "c2d" ] || [ "$SUBFLOW" = "d2c" ] || [ "$SUBFLOW" = "e2f" ] || [ "$SUBFLOW" = "f2e" ];then
				SUBFLOW="B"
		    fi
		    
		    if [ "$SUBFLOW" = "g2h" ] || [ "$SUBFLOW" = "h2g" ];then
				SUBFLOW="C"
		    fi
			#Extrac CDF
			cat ${PLOT_FILES[$fe]} | awk '{printf "%.2f \n",$2}' | sort -n | uniq -c | sort -k2 -n > $TMPFILE
			#echo " ${PLOT_FILES[$fe]}"
			TOTAL=`awk '{sum+=$1}END{print sum}' $TMPFILE`
			#echo $TOTAL
			awk 'BEGIN{sum=0; tot='$TOTAL'} sum+=$1/tot {printf "%.3f %.5f\n",$2,sum}' $TMPFILE | sort -k1 -n > $TMPPLOT
			#gnucmd+="'$TMPPLOT' using 1:2 notitle smooth bezier ls  $index, "
			gnucmd+="'$TMPPLOT' every 10 using 1:2 title '$SUBFLOW' with linespoints ls $index , "
			


			#cp ${PLOT_FILES[$fe]} ${gPATH}
		fi
	done
	echo -e "$gnucmd" | gnuplot

	Clean
	
	
}

PlotCumulatives(){

	F_PREFIX=$1
	FILETYPEX=$2
	PLOT_FILES=(`ls ${gPATH}/ | grep .plot| grep ${F_PREFIX%.*} | grep $FILETYPEX`)

	xLABEL=$FILETYPEX
	if [ "$FILETYPEX" = "tput" ];then
		xLABEL="Vazão (Mbps)"
	fi

	if [ "$FILETYPEX" = "rtt" ];then
		xLABEL="RTT (ms)"
	fi


	cd ${gPATH}

	gnucmd=`echo "
	########################### BEGIN ####################################
	reset
	#formato de codificação
	set termoption dashed
	set encoding utf8

	#formato do arquivo, estilo da fonte e tamanho da fonte
	set terminal postscript eps enhanced  color 'Helvetica, 36'

	#arquivo de saída em formato pdf
	set output '| epstopdf --filter > ${pPATH}/cum-$FILETYPEX-${F_PREFIX}.pdf'

	set style line 1 lc rgb '#000000' lt 1 dashtype 3 lw 3 pt 64 ps 2.5 #pi -1
	set style line 2 lc rgb '#000000' lt 2 dashtype 4 lw 3 pt 65 ps 2.5 #pi -1
	set style line 3 lc rgb '#000000' lt 3 dashtype 5 lw 3 pt 66 ps 2.5 #pi -1
	set style line 4 lc rgb '#000000' lt 4 dashtype 6 lw 3 pt 68 ps 2.5 #pi -1
	set style line 5 lc rgb '#000000' lt 2 dashtype '-' lw 0.2
	
	set ytics font 'Helvetica,24' 0.0,0.20,1.0
	set xtics font 'Helvetica,24'


	#set title 'Dados Acumulados' font 'Helvetica,32'
	set xlabel 'Tempo (s)' font 'Helvetica,36'
	#set ylabel 'Dados Acumulados (%)' font 'Helvetica,28'

	set yrange [0:1]
	set xrange [0:60]
	set key right bottom samplen 4 font 'Helvetica,26' reverse Left

	set size 1,1
	set grid ytics ls 5
	set grid xtics ls 5

	#set lmargin at screen 0.1;
	#set rmargin at screen 0.1;
	#set bmargin at screen 0.25;
	#set tmargin at screen 0.95;
	
	"`
	gnucmd+="plot "


	TMPFILE="file.tmp"

	for (( fe=0; fe<${#PLOT_FILES[@]}; ++fe )) 
	do
		

		if [[ -s "${PLOT_FILES[$fe]}" ]] 
		then
			index=$(($fe + 1))	
			TMPPLOT="cum-$index-${PLOT_FILES[$fe]}.tmp"
			SUBFLOW=`echo ${PLOT_FILES[$fe]} | rev | cut -c1-8 | rev | cut -d'.' -f1`
			if [ "$SUBFLOW" = "a2b" ] || [ "$SUBFLOW" = "b2a" ];then
				SUBFLOW="A"
		    fi

		    if [ "$SUBFLOW" = "c2d" ] || [ "$SUBFLOW" = "d2c" ] || [ "$SUBFLOW" = "e2f" ] || [ "$SUBFLOW" = "f2e" ];then
				SUBFLOW="B"
		    fi
		    
		    if [ "$SUBFLOW" = "g2h" ] || [ "$SUBFLOW" = "h2g" ];then
				SUBFLOW="C"
		    fi

			TOTAL=`awk '{sum+=$2}END{print sum}' ${PLOT_FILES[$fe]}`
			awk 'BEGIN{sum=0; tot='$TOTAL'} sum+=$2/tot {printf "%.3f %.5f\n",$1,sum}' ${PLOT_FILES[$fe]} > $TMPPLOT
			
			gnucmd+="'$TMPPLOT' every 100 using 1:2 title '$SUBFLOW' with linespoints ls $index , "
			echo $index

		fi
	done
	echo -e "$gnucmd" | gnuplot

	Clean	
	
}

PlotTHP(){


	#get name_prefix of plot files from work dir
	PLOT_PREFIX=(`ls ${gPATH} | grep plot | rev| cut -c10- | rev | uniq`)


	# for each file, verify the number of plot files (expect 4)
	for (( filep=0; filep<${#PLOT_PREFIX[@]}; ++filep ))
	do

			F_PREFIX=${PLOT_PREFIX[$filep]}

			cd ${gPATH}

			PLOT_FILES=(`ls ${gPATH}/ | grep .plot| grep ${F_PREFIX} | grep ^tput-`)

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
			set xdata time

			#set yrange ${yRANGE}
			#set xrange [0:65]

			set ytics font 'Helvetica,16'
			set xtics font 'Helvetica,16'

			#cria estilo para a caixa e os pontos
			set style line 1 lc rgb '#00f9ff' lt 1 dashtype 1 lw 1 pt 64
			set style line 2 lc rgb '#d600ff' lt 1 dashtype 1 lw 1 pt 66
			set style line 3 lc rgb '#f0ff00' lt 1 dashtype 1 lw 1 pt 68
			set style line 4 lc rgb '#00FF00' lt 1 dashtype 1 lw 1 pt 67
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
					gnucmd+="'${PLOT_FILES[$fe]}' using (\$1-946684800.0):(\$2/1024/1024/8) t 'Path $SUBFLOW' with points ls $index , "
					#cp ${PLOT_FILES[$fe]} ${gPATH}
				fi
			done

			echo -e "$gnucmd" | gnuplot

			cd ${vPATH}
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
	

	set title '$gTITLE' font 'Helvetica,32'
	set xlabel 'Tempo (s)' font 'Helvetica,28'
	set ylabel '$yLABEL' font 'Helvetica,28'
	#set format x '%.0f'
	set format y '%.1f'
	#set xdata time

	#set yrange [-0.5:]
	set xrange [0:60]

	set ytics font 'Helvetica,22'
	set xtics font 'Helvetica,22'

	#set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 pi -1 ps 1.5
	#set pointintervalbox 3

	#cria estilo para a caixa e os pontos
	set style line 1 lc rgb '#0000ff' lt -1 dashtype 4 lw 3 pt 66  ps 1
	set style line 2 lc rgb '#ff0000' lt -1 dashtype 2 lw 3 pt 2   ps 1 #pula
	set style line 3 lc rgb '#0d0d0d' lt -1 dashtype 3 lw 3 pt 68  ps 1
	set style line 4 lc rgb '#ff0000' lt -1 dashtype 2 lw 2 pt 3   ps 1
	
	set pointsize 1
	
	set style line 5 lc rgb '#696969' lt 2 dashtype '-.' lw 0.5

	#posição da legenda
	#set key outside
	#set key horiz
	set key bottom right samplen 4 font 'Helvetica,14' reverse Left

	#cria a grade
	set grid ytics ls 5
	set grid xtics ls 5
	" `

	gnucmd+="plot "
	index=0
	for (( fe=0; fe<${#PLOT_FILES[@]}; ++fe )) 
	do
		if [[ -s "${PLOT_FILES[$fe]}" ]] 
		then
			index=$(($fe + 1))

			if [ "$SUBFLOW" = "a2b" ];then
				SUBFLOW="A"
		    fi

		    if [ "$SUBFLOW" = "c2d" ];then
				SUBFLOW="B"
		    fi
		    
		    if [ "$SUBFLOW" = "g2h" ];then
				SUBFLOW="C"
		    fi

			SUBFLOW=`echo ${PLOT_FILES[$fe]} | rev | cut -c1-8 | rev | cut -d'.' -f1`
			gnucmd+="'${PLOT_FILES[$fe]}' using 1:2 t 'Path $SUBFLOW' w points ls $index , "
			gnucmd+="'${PLOT_FILES[$fe]}' using 1:2 notitle with lines ls $index , "
			#cp ${PLOT_FILES[$fe]} ${gPATH}
		fi
	done
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

		if [ "$yLABEL" = "TPUT" ];then
				yLABEL="Vazão (Mbps)"
		fi

		if [ "$yLABEL" = "RTT" ];then
				yLABEL="RTT (ms)"
		fi

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
	#Clean plot
	#Clean xpl 
	cd ${gPATH}


	PCAPS=(`ls ${sPATH} | grep pcap | grep c1`)
	echo -e "${RED}==> Analysis of ${#PCAPS[@]} pcaps <==${NOCOLOR}"
	for (( filep=0; filep<${#PCAPS[@]}; ++filep ))
	do
				
		
		echo ${PCAPS[$filep]}

		
		#AnalysisCWND ${PCAPS[$filep]}
		
		#AnalysisLosses ${PCAPS[$filep]}
		
		#AnalysisDupACK ${PCAPS[$filep]}
		#AnalysisRetransmissions ${PCAPS[$filep]}
		
		#Usar apenas em conjunto
		#AnalysisThroughput ${PCAPS[$filep]}
		#PlotTHP

		#AnalysisRTT ${PCAPS[$filep]}
		#AnalysisThroughput2 ${PCAPS[$filep]}
		#AnalysisSequenceNumber ${PCAPS[$filep]}

		PlotCDF ${PCAPS[$filep]} "tput"
		PlotCDF ${PCAPS[$filep]} "rtt"

		PlotCumulatives ${PCAPS[$filep]} "dupack"
		PlotCumulatives ${PCAPS[$filep]} "ret"
		

	done

	#Plot
}

Frequencies(){
	FQS=(`ls ${gPATH} | grep rtt`)
	echo -e "${RED}==> Plot of ${#FQS[@]} pcaps <==${NOCOLOR}"
	for (( filep=0; filep<${#FQS[@]}; ++filep ))
	do
	
	 echo "PlotFrequencies $filep"
	 PlotFrequencies ${FQS[$filep]}

	done
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

main()
{
     Analysis
     #Frequencies
}

main "$@"