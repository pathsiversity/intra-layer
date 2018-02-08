#!/bin/bash

awk 'BEGIN{
	while (getline < "dssn.t2x") {
		filea[$1]=+1;
	}
}
{	
	if(filea[$1]>0)
		printf "%s %s \n", $1, filea[$1]
}' dssn.t1