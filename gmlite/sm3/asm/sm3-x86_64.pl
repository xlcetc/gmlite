#! /usr/bin/env perl

# Copyright 2020 Meng-Shan Jiang, Lu-Lu Han. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
# 
# SM3 avx2 was originally written by Lu-Lu Han in GNU ASM, I did some 
# optimization and rewrited it in perl.


$CC = shift;
$flavour = shift;
$output  = shift;

if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

$avx = 2;
$addx = 1;

my ($a,$b,$c,$d,$e,$f,$g,$h)=("%eax","%ebx","%ecx","%r8d","%edx","%r9d","%r10d","%r11d");
# my ($X0,$X1,$X2,$X3)=("%ymm4","%ymm5","%ymm6","%ymm7");
my ($XWORD0,$XWORD1,$XWORD2,$XWORD3)=("%xmm4","%xmm5","%xmm6","%xmm7");
my ($XTMP0,$XTMP1,$XTMP2,$XTMP3,$XTMP4,$XFER,$XTMP5)=("%ymm0","%ymm1","%ymm2","%ymm3","%ymm8","%ymm9","%ymm11");
my ($SHUF_00BA,$SHUF_DC00)=("$ymm10","$ymm12");
my ($BYTE_FLIP_MASK,$X_BYTE_FLIP_MASK)=("%ymm13","%xmm13");
my ($CTX,$INP,$NUM_BLKS)=("%rdi","%rsi","%rdx");
my ($SRND,$TBL)=("%rdi","%r12");
my ($y0,$y1,$y2,$y3)=("%r13d","%r14d","%r15d","%esi");

$_XFER_SIZE = 2*64*4;
$_XMM_SAVE_SIZE = 2*64*4;
$_INP_END_SIZE = 8;
$_INP_SIZE = 8;
$_CTX_SIZE = 8;
$_RSP_SIZE = 8;

$_XFER      = 0;
$_XMM_SAVE  = $_XFER     + $_XFER_SIZE;
$_INP_END   = $_XMM_SAVE+$_XMM_SAVE_SIZE;
$_INP       = $_INP_END  + $_INP_END_SIZE;
$_CTX       = $_INP      + $_INP_SIZE;
$_RSP       = $_CTX      + $_CTX_SIZE;
$STACK_SIZE = $_RSP      + $_RSP_SIZE;

$code.=<<___;
.text

# The polynomial
.align 64
K256:
    .long 0x79CC4519,0xF3988A32,0xE7311465,0xCE6228CB
    .long 0x9CC45197,0x3988A32F,0x7311465E,0xE6228CBC
    .long 0xCC451979,0x988A32F3,0x311465E7,0x6228CBCE
    .long 0xC451979C,0x88A32F39,0x11465E73,0x228CBCE6
    .long 0x9D8A7A87,0x3B14F50F,0x7629EA1E,0xEC53D43C
    .long 0xD8A7A879,0xB14F50F3,0x629EA1E7,0xC53D43CE
    .long 0x8A7A879D,0x14F50F3B,0x29EA1E76,0x53D43CEC
    .long 0xA7A879D8,0x4F50F3B1,0x9EA1E762,0x3D43CEC5
    .long 0x7A879D8A,0xF50F3B14,0xEA1E7629,0xD43CEC53
    .long 0xA879D8A7,0x50F3B14F,0xA1E7629E,0x43CEC53D
    .long 0x879D8A7A,0x0F3B14F5,0x1E7629EA,0x3CEC53D4
    .long 0x79D8A7A8,0xF3B14F50,0xE7629EA1,0xCEC53D43
    .long 0x9D8A7A87,0x3B14F50F,0x7629EA1E,0xEC53D43C
    .long 0xD8A7A879,0xB14F50F3,0x629EA1E7,0xC53D43CE
    .long 0x8A7A879D,0x14F50F3B,0x29EA1E76,0x53D43CEC
    .long 0xA7A879D8,0x4F50F3B1,0x9EA1E762,0x3D43CEC5

PSHUFFLE_BYTE_FLIP_MASK:
.quad 0x0405060700010203,0x0c0d0e0f08090a0b,0x0405060700010203,0x0c0d0e0f08090a0b
# .octa 0x0c0d0e0f08090a0b0405060700010203,0x0c0d0e0f08090a0b0405060700010203
___

sub FIRST_16_ROUNDS_AND_SCHED()
{
    my ($X0,$X1,$X2,$X3) = @_;
$code.=<<___;
    mov $a, $y1
    vpalignr \$12, $X0, $X1, $XTMP0		#--1--(W[-13],W[-12],W[-11],W[-10])
    rorxl \$20, $a, $y0					#ROTATELEFT(A,12)
    xorl $b, $y1
    movl $y0, $y2						#ROTATELEFT(A,12)
    vpslld \$7, $XTMP0, $XTMP1		    #--2--((W[-13],W[-12],W[-11],W[-10]) << 7)
    addl $e, $y0
    xorl $c, $y1						#FF0(A, $B, $C)
    addl 0($TBL), $y0
    add \$4, $TBL
    movl $e, $y3
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)
    vpsrld \$25, $XTMP0, $XTMP2		#--3--((W[-13],W[-12],W[-11],W[-10] >> 25)
    xorl $f, $y3
    xorl $y0, $y2						#ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)
    addl $d, $y1						#FF0(A, $B, $C)+D
    vpxor $XTMP1, $XTMP2, $XTMP0		#--4--((W[-13],W[-12],W[-11],W[-10] <<< 17)
    rorxl \$23, $b, $b					#ROTATELEFT(B,9);
    addl $y1, $y2						#FF0(A, $B, $C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)
    addl $h, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)
    addl $_XFER+0*4(%rsp,$SRND,1), $y2		#FF0(A, $B, $C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)+W'[j]
    xorl $g, $y3						#GG0(E,F,G)
    addl $_XMM_SAVE+0*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j]
    vpalignr \$8, $X2, $X3, $XTMP2		#--5--(W[-6],W[-5],W[-4],W[-3])
    rorxl \$13, $f, $f					#ROTATELEFT(F,19);
    addl $y0, $y3						#GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j]
    vpxor $XTMP2, $XTMP0, $XTMP0		#--6--(W[-6],W[-5],W[-4],W[-3])^((W[-13],W[-12],W[-11],W[-10] <<< 17)
    rorxl \$23, $y3, $h
    movl $y2, $d
    vpshufd \$0b00111001, $X3, $XTMP1	#--7--(W[-3],W[-2],W[-1],W[0])
    xorl $y3, $h
    rorxl \$15, $y3, $y1
    vpslld \$15, $XTMP1, $XTMP2		#--8--((W[-3],W[-2],W[-1],W[0]) << 15)
    xorl $y1, $h                       #P0(GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j])

    movl $d, $y1
    rorxl \$20, $d, $y0						#ROTATELEFT(A,12)
    xorl $a, $y1
    movl $y0, $y2						#ROTATELEFT(A,12)
    vpsrld \$17, $XTMP1, $XTMP1		#--9--((W[-3],W[-2],W[-1],W[0]) >> 17)
    addl $h, $y0
    xorl $b, $y1						#FF0(A, $B, $C)
    addl 0($TBL), $y0
    add \$4, $TBL
    vpxor $XTMP1, $XTMP2, $XTMP1		#--10--((W[-3],W[-2],W[-1],W[0]) <<< 15)
    movl $h, $y3
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)
    addl $c, $y1						#FF0(A, $B, $C)+D
    vpalignr \$12, $X1, $X2, $XTMP2		#--11--(W[-9],W[-8],W[-7],W[-6])
    xorl $e, $y3
    xorl $y0, $y2						#ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)
    rorxl \$23, $a, $a					#ROTATELEFT(B,9);
    vpxor $X0, $XTMP2, $XTMP2			#--12--(W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])
    addl $y1, $y2						#FF0(A, $B, $C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)
    addl $g, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)
    addl $_XFER+1*4(%rsp,$SRND,1), $y2		#FF0(A, $B, $C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)+W'[j]
    vpxor $XTMP2, $XTMP1, $XTMP1		#--13--(W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])^((W[-3],W[-2],W[-1],W[0]) <<< 15)
    xorl $f, $y3						#GG0(E,F,G)
    addl $_XMM_SAVE+1*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j]
    rorxl \$13, $e, $e					#ROTATELEFT(F,19);
    vpslld \$15, $XTMP1, $XTMP3		#--14--P1(x)--> X << 15
    addl $y0, $y3						#GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j]
    movl $y2, $c
    rorxl \$23, $y3, $g
    vpsrld \$17, $XTMP1, $XTMP4		#--15--P1(x)--> X >> 17
    xorl $y3, $g
    rorxl \$15, $y3, $y1
    vpxor $XTMP3, $XTMP4, $XTMP3		#--16--P1(x)--> x <<< 15
    xorl $y1, $g						#P0(GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j])  

    movl $c, $y1
    vpslld \$23, $XTMP1, $XTMP4		#--17--P1(x)--> X << 23
    rorxl \$20, $c, $y0					#ROTATELEFT(A,12)
    xorl $d, $y1
    movl $y0, $y2						#ROTATELEFT(A,12)
    vpsrld \$9, $XTMP1, $XTMP5			#--18--P1(x)--> X >> 9
    addl $g, $y0
    xorl $a, $y1						#FF0(A, $B, $C)
    vpxor $XTMP5, $XTMP4, $XTMP4		#--19--P1(x)--> X <<< 23
    addl 0($TBL), $y0
    add \$4, $TBL
    movl $g, $y3
    rorxl \$23, $d, $d					#ROTATELEFT(B,9);
    vpxor $XTMP3, $XTMP1, $XTMP1		#--20--P1(x)--> x ^ (x <<< 15)
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)
    addl $b, $y1						#FF0(A, $B, $C)+D
    xorl $h, $y3
    vpxor $XTMP4, $XTMP1, $XTMP1		#--21--P1(x)==x ^ (x <<< 15) ^ (X <<< 23)
    xorl $y0, $y2						#ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)
    addl $f, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)
    vpxor $XTMP0, $XTMP1, $XTMP1		#--22--(W[0],W[1],W[2],W[3])
    addl $y1, $y2						#FF0(A, $B, $C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)
    xorl $e, $y3						#GG0(E,F,G)
    addl $_XFER+2*4(%rsp,$SRND,1), $y2		#FF0(A, $B, $C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)+W'[j]
    vpshufd \$0b00000000, $XTMP1, $XTMP3 #--23--(W[0],W[0],W[0],W[0])
    addl $_XMM_SAVE+2*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j]
    movl $y2, $b
    vpsllq \$15, $XTMP3, $XTMP3		#--24--(W[0],W[0] <<< 15,W[0],W[0])
    addl $y0, $y3						#GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j]
    rorxl \$13, $h, $h					#ROTATELEFT(F,19);
    vpshufd \$0b01010101, $XTMP3, $XTMP3 #--25--
    rorxl \$23, $y3, $f
    xorl $y3, $f
    vpxor $XTMP3, $XTMP2, $XTMP2		#--26--((W[0] <<< 15) ^ $XTMP2,W[0],W[0],W[0])
    rorxl \$15, $y3, $y1
    vpshufd \$0b11111111, $XTMP2, $XTMP3 #--27--(X,X,X,X)
    xorl $y1, $f                       #P0(GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j])

    movl $b, $y1
    vpsllq \$15, $XTMP3, $XTMP4		#--28--(X,X <<< 15,X,X)
    rorxl \$20, $b, $y0					#ROTATELEFT(A,12)
    xorl $c, $y1
    vpsllq \$23, $XTMP3, $XTMP5		#--29--(X,X <<< 23,X,X)
    movl $y0, $y2						#ROTATELEFT(A,12)
    movl $f, $y3
    addl $f, $y0
    vpxor $XTMP5, $XTMP4, $XTMP4		#--30--(X,(X <<< 23) ^ (X <<< 15),X,X)
    xorl $d, $y1						#FF0(A, $B, $C)
    addl 0($TBL), $y0
    add \$4, $TBL
    xorl $g, $y3
    vpshufd \$0b01010101, $XTMP4, $XTMP4 #--31--((X <<< 23) ^ (X <<< 15),(X <<< 23) ^ (X <<< 15),(X <<< 23) ^ (X <<< 15),(X <<< 23) ^ (X <<< 15))
    rorxl \$23, $c, $c					#ROTATELEFT(B,9);
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)
    xorl $h, $y3						#GG0(E,F,G)
    vpxor $XTMP4, $XTMP3, $XTMP3       #--32-((X <<< 23) ^ (X <<< 15) ^ X,(X <<< 23) ^ (X <<< 15) ^ X,(X <<< 23) ^ (X <<< 15) ^ X,(X <<< 23) ^ (X <<< 15) ^ X)
    xorl $y0, $y2						#ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)
    addl $a, $y1						#FF0(A, $B, $C)+D
    addl $e, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)
    vpxor $XTMP3, $XTMP0, $XTMP0		#--33--
    addl $y1, $y2						#FF0(A, $B, $C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)
    addl $_XMM_SAVE+3*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j]
    addl $_XFER+3*4(%rsp,$SRND,1), $y2		#FF0(A, $B, $C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7) ^ ROTATELEFT(A,12)+W'[j]
    vpalignr \$12, $XTMP0, $XTMP1, $XTMP0	#--34--
    addl $y0, $y3						#GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, $7)+W[j]
    movl $y2, $a
    rorxl \$23, $y3, $e
    vpshufd \$0b00111001, $XTMP0, $XTMP0 #--35--
    rorxl \$13, $g, $g					#ROTATELEFT(F,19);
    xorl $y3, $e
    rorxl \$15, $y3, $y1
    vmovdqa $XTMP0, $X0				#--36--
    xorl $y1, $e
___
}


sub SECOND_36_ROUNDS_AND_SCHED()
{   
    my ($X0,$X1,$X2,$X3) = @_;
$code.=<<___;
    vpalignr \$12, $X0, $X1, $XTMP0		#--1--(W[-13],W[-12],W[-11],W[-10])
    movl $b, $y1
    movl $c, $y2
    rorxl \$20, $a, $y0					#ROTATELEFT(A,12)
    vpslld \$7, $XTMP0, $XTMP1		    #--2--((W[-13],W[-12],W[-11],W[-10]) << 7)
    or $c, $y1						#(B|C)
    andl $b, $y2						#(B&C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $a, $y1						#A&(B|C)
    vpsrld \$25, $XTMP0, $XTMP2		#--3--((W[-13],W[-12],W[-11],W[-10] >> 25)
    rorxl \$23, $b, $b					#ROTATELEFT(B,9);
    addl $e, $y0
    or $y2, $y1						#FF1(x,y,z)
    vpxor $XTMP1, $XTMP2, $XTMP0		#--4--((W[-13],W[-12],W[-11],W[-10] <<< 17)
    addl 0($TBL), $y0
    add \$4, $TBL
    addl $d, $y1						#FF1(A, B, C)+D
    movl $f, $y2
    rorxl \$25, $y0, $y0				#SS1=ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    vpalignr \$8, $X2, $X3, $XTMP2		#--5--(W[-6],W[-5],W[-4],W[-3])
    xorl $g, $y2
    xorl $y0, $y3						#SS2=ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    vpxor $XTMP2, $XTMP0, $XTMP0		#--6--(W[-6],W[-5],W[-4],W[-3])^((W[-13],W[-12],W[-11],W[-10] <<< 17)
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $h, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    andl $e, $y2
    addl $_XFER+0*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    vpshufd \$0b00111001, $X3, $XTMP1	#--7--(W[-3],W[-2],W[-1],W[0])
    addl $_XMM_SAVE+0*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    xorl $g, $y2
    movl $y3, $d
    rorxl \$13, $f, $f					#ROTATELEFT(F,19);
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    vpslld \$15, $XTMP1, $XTMP2		#--8--((W[-3],W[-2],W[-1],W[0]) << 15)
     movl $a, $y1
    rorxl \$23, $y0, $h
    rorxl \$15, $y0, $y3
    xorl $y0, $h
    vpsrld \$17, $XTMP1, $XTMP1		#--9--((W[-3],W[-2],W[-1],W[0]) >> 17)
     movl $b, $y2
    xorl $y3, $h						#P0(GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j])

    vpxor $XTMP1, $XTMP2, $XTMP1		#--10--((W[-3],W[-2],W[-1],W[0]) <<< 15)
    rorxl \$20, $d, $y0					#ROTATELEFT(A,12)
    or $b, $y1						#(B|C)
    vpalignr \$12, $X1, $X2, $XTMP2		#--11--(W[-9],W[-8],W[-7],W[-6])
    andl $a, $y2						#(B&C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $d, $y1						#A&(B|C)
    vpxor $X0, $XTMP2, $XTMP2			#--12--(W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])
    rorxl \$23, $a, $a					#ROTATELEFT(B,9);
    addl $h, $y0
    or $y2, $y1						#FF1(x,y,z)
    vpxor $XTMP2, $XTMP1, $XTMP1		#--13--(W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])^((W[-3],W[-2],W[-1],W[0]) <<< 15)
    addl 0($TBL), $y0
    add \$4, $TBL
    addl $c, $y1						#FF1(A, B, C)+D
    vpslld \$15, $XTMP1, $XTMP3		#--14--P1(x)--> X << 15
    rorxl \$25, $y0, $y0				#SS1=ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    movl $e, $y2
    vpsrld \$17, $XTMP1, $XTMP4		#--15--P1(x)--> X >> 17
    xorl $y0, $y3						#SS2=ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    xorl $f, $y2
    addl $g, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    vpxor $XTMP3, $XTMP4, $XTMP3		#--16--P1(x)--> x <<< 15
    movl $e, $y1
    andl $h, $y2
    addl $_XMM_SAVE+1*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    vpslld \$23, $XTMP1, $XTMP4		#--17--P1(x)--> X << 23
    xorl $f, $y2
    addl $_XFER+1*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    rorxl \$13, $e, $e					#ROTATELEFT(F,19);
    movl $y3, $c
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    vpsrld \$9, $XTMP1, $XTMP5			#--18--P1(x)--> X >> 9
     movl $d, $y1
    rorxl \$23, $y0, $g
    rorxl \$15, $y0, $y3
    xorl $y0, $g
    vpxor $XTMP5, $XTMP4, $XTMP4		#--19--P1(x)--> X <<< 23
     movl $a, $y2
    xorl $y3, $g

    rorxl \$20, $c, $y0					#ROTATELEFT(A,12)
    vpxor $XTMP3, $XTMP1, $XTMP1		#--20--P1(x)--> x ^ (x <<< 15)
    or $a, $y1						#(B|C)
    andl $d, $y2						#(B&C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $c, $y1						#A&(B|C)
    vpxor $XTMP4, $XTMP1, $XTMP1		#--21--P1(x)==x ^ (x <<< 15) ^ (X <<< 23)
    rorxl \$23, $d, $d					#ROTATELEFT(B,9);
    addl $g, $y0
    or $y2, $y1						#FF1(x,y,z)
    vpxor $XTMP0, $XTMP1, $XTMP1		#--22--(W[0],W[1],W[2],W[3])
    addl 0($TBL), $y0
    add \$4, $TBL
    movl $h, $y2
    addl $b, $y1						#FF1(A, B, C)+D
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    vpshufd \$0b00000000,$XTMP1,$XTMP3 #--23--(W[0],W[0],W[0],W[0])
    xorl $e, $y2
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $f, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    vpsllq \$15, $XTMP3, $XTMP3		#--24--(W[0],W[0] <<< 15,W[0],W[0])
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    andl $g, $y2
    addl $_XFER+2*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    vpshufd \$0b01010101,$XTMP3,$XTMP3 #--25--
    addl $_XMM_SAVE+2*4(%rsp,$SRND,1),$y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    xorl $e, $y2
    movl $y3, $b
    vpxor $XTMP3, $XTMP2, $XTMP2		#--26--((W[0] <<< 15) ^ $XTMP2,W[0],W[0],W[0])
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $h, $h					#ROTATELEFT(F,19)
     movl $c, $y1
    rorxl \$23, $y0, $f
    rorxl \$15, $y0, $y3
    xorl $y0, $f
    vpshufd \$0b11111111,$XTMP2,$XTMP3 #--27--(X,X,X,X)
     movl $d, $y2
    xorl $y3, $f

    vpsllq \$15, $XTMP3, $XTMP4		#--28--(X,X <<< 15,X,X)
    rorxl \$20, $b, $y0					#ROTATELEFT(A,12)
    or $d, $y1						#(B|C)
    vpsllq \$23, $XTMP3, $XTMP5		#--29--(X,X <<< 23,X,X)
    andl $c, $y2						#(B&C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $b, $y1						#A&(B|C)
    vpxor $XTMP5,$XTMP4, $XTMP4		#--30--(X,(X <<< 23) ^ (X <<< 15),X,X)
    rorxl \$23, $c, $c					#ROTATELEFT(B,9);
    addl $f, $y0
    or $y2, $y1						#FF1(x,y,z)
    vpshufd \$0b01010101,$XTMP4,$XTMP4 #--31--((X <<< 23) ^ (X <<< 15),(X <<< 23) ^ (X <<< 15),(X <<< 23) ^ (X <<< 15),(X <<< 23) ^ (X <<< 15))
    addl 0($TBL), $y0
    add \$4, $TBL
    movl $g, $y2
    addl $a, $y1						#FF1(A, B, C)+D
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    vpxor $XTMP4,$XTMP3,$XTMP3       #--32-((X <<< 23) ^ (X <<< 15) ^ X,(X <<< 23) ^ (X <<< 15) ^ X,(X <<< 23) ^ (X <<< 15) ^ X,(X <<< 23) ^ (X <<< 15) ^ X)
    xorl $h, $y2
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $e, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    vpxor $XTMP3, $XTMP0, $XTMP0		#--33--
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    andl $f, $y2
    addl $_XFER+3*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    vpalignr \$12,$XTMP0,$XTMP1, $XTMP0	#--34--
    xorl $h, $y2
    addl $_XMM_SAVE+3*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    movl $y3, $a
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    vpshufd \$0b00111001,$XTMP0,$XTMP0 #--35--
    rorxl \$13, $g, $g					#ROTATELEFT(F,19);
    rorxl \$23, $y0, $e
    rorxl \$15, $y0, $y3
    xorl $y0, $e
    vmovdqa $XTMP0, $X0				#--36--
    xorl $y3, $e
___
}


sub THIRD_12_ROUNDS_AND_SCHED()
{   
    my ($X0,$X1,$X2,$X3) = @_;
$code.=<<___;
    movl $b, $y1
    rorxl \$20, $a, $y0					#ROTATELEFT(A,12)
    movl $c, $y2
    or $c, $y1						#(B|C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $b, $y2						#(B&C)
    andl $a, $y1						#A&(B|C)
    addl $e, $y0
    or $y2, $y1						#FF1(x,y,z)
    addl 0($TBL), $y0
    add \$4, $TBL
    addl $d, $y1						#FF1(A, B, C)+D
    movl $f, $y2
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    xorl $g, $y2
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $h, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $_XMM_SAVE+0*4(%rsp,$SRND,1),$y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    andl $e, $y2
    addl $_XFER+0*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    rorxl \$23, $b,  $b					#ROTATELEFT(B,9);
    xorl $g, $y2
    movl $y3, $d
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $f, $f					#ROTATELEFT(F,19);
     movl $a, $y1
    rorxl \$23, $y0, $h
    rorxl \$15, $y0, $y3
    xorl $y0, $h
     movl $b, $y2
     rorxl \$20, $d, $y0					#ROTATELEFT(A,12)
    xorl $y3, $h

    or $b, $y1						#(B|C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $a, $y2						#(B&C)
    andl $d, $y1						#A&(B|C)
    addl $h, $y0
    or $y2, $y1						#FF1(x,y,z)
    addl 0($TBL), $y0
    add \$4, $TBL
    addl $c, $y1						#FF1(A, B, C)+D
    movl $e, $y2
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    xorl $f, $y2
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $g, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $_XMM_SAVE+1*4(%rsp,$SRND,1),$y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    andl $h, $y2
    addl $_XFER+1*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    rorxl \$23, $a, $a					#ROTATELEFT(B,9);
    xorl $f, $y2
    movl $y3, $c
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $e, $e					#ROTATELEFT(F,19);
     movl $d, $y1
    rorxl \$23, $y0, $g
    rorxl \$15, $y0, $y3
    xorl $y0, $g
     movl $a, $y2
     rorxl \$20, $c, $y0					#ROTATELEFT(A,12)
    xorl $y3, $g

    or $a, $y1						#(B|C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $d, $y2						#(B&C)
    andl $c, $y1						#A&(B|C)
    addl $g, $y0
    or $y2, $y1						#FF1(x,y,z)
    addl 0($TBL), $y0
    add \$4, $TBL
    addl $b, $y1						#FF1(A, B, C)+D
    movl $h, $y2
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    xorl $e, $y2
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $f, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $_XMM_SAVE+2*4(%rsp,$SRND,1),$y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    andl $g, $y2
    addl $_XFER+2*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    rorxl \$23, $d, $d					#ROTATELEFT(B,9);
    xorl $e, $y2
    movl $y3, $b
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $h, $h					#ROTATELEFT(F,19);
     movl $c, $y1
    rorxl \$23, $y0, $f
    rorxl \$15, $y0, $y3
    xorl $y0, $f
     movl $d, $y2
     rorxl \$20, $b, $y0					#ROTATELEFT(A,12)
    xorl $y3, $f

    or $d, $y1						#(B|C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $c, $y2						#(B&C)
    andl $b, $y1						#A&(B|C)
    addl $f, $y0
    or $y2, $y1						#FF1(x,y,z)
    addl 0($TBL), $y0
    add \$4, $TBL
    addl $a, $y1						#FF1(A, B, C)+D
    movl $g, $y2
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    xorl $h, $y2
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $e, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $_XMM_SAVE+3*4(%rsp,$SRND,1),$y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    andl $f, $y2
    addl $_XFER+3*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    rorxl \$23, $c, $c					#ROTATELEFT(B,9);
    xorl $h, $y2
    movl $y3, $a
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $g, $g					#ROTATELEFT(F,19);
    rorxl \$23, $y0, $e
    rorxl \$15, $y0, $y3
    xorl $y0, $e
    xorl $y3, $e
___
}


sub FIRST_16_ROUNDS_WITHOUT_SCHED()
{   
$code.=<<___;
    movl $a, $y1
    rorxl \$20, $a, $y0					#ROTATELEFT(A,12)
    movl $e, $y3
    xorl $b, $y1
    movl $y0, $y2						#ROTATELEFT(A,12)
    addl $e, $y0
    xorl $c, $y1						#FF0(A, B, C)
    addl 0($TBL), $y0
    add \$4, $TBL
    xorl $f, $y3
    addl $d, $y1						#FF0(A, B, C)+D
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    rorxl \$23, $b,  $b					#ROTATELEFT(B,9);
    xorl $y0, $y2						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    xorl $g, $y3						#GG0(E,F,G)
    addl $y1, $y2						#FF0(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $h, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $_XFER+0*4(%rsp,$SRND,1), $y2	#FF0(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    addl $_XMM_SAVE+0*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    movl $y2, $d
    addl $y0, $y3						#GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $f, $f					#ROTATELEFT(F,19);
    rorxl \$23, $y3, $h
    rorxl \$15, $y3, $y1
    xorl $y3, $h
    xorl $y1, $h                       #P0(GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j])

    movl $d, $y1
    rorxl \$20, $d, $y0					#ROTATELEFT(A,12)
    xorl $a, $y1
    movl $h, $y3
    movl $y0, $y2						#ROTATELEFT(A,12)
    addl $h, $y0
    xorl $b, $y1						#FF0(A, B, C)
    addl 0($TBL), $y0
    add \$4, $TBL
    xorl $e, $y3
    addl $c, $y1						#FF0(A, B, C)+D
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    rorxl \$23, $a,  $a					#ROTATELEFT(B,9);
    xorl $y0, $y2						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    xorl $f, $y3						#GG0(E,F,G)
    addl $y1, $y2						#FF0(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $g, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $_XFER+1*4(%rsp,$SRND,1), $y2	#FF0(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    addl $_XMM_SAVE+1*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    movl $y2, $c
    addl $y0, $y3						#GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $e, $e					#ROTATELEFT(F,19);
    rorxl \$23, $y3, $g
    rorxl \$15, $y3, $y1
    xorl $y3, $g
    xorl $y1, $g                       #P0(GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j])

    movl $c, $y1
    rorxl \$20, $c, $y0					#ROTATELEFT(A,12)
    xorl $d, $y1
    movl $g, $y3
    movl $y0, $y2						#ROTATELEFT(A,12)
    addl $g, $y0
    xorl $a, $y1						#FF0(A, B, C)
    addl 0($TBL), $y0
    add \$4, $TBL
    xorl $h, $y3
    addl $b, $y1						#FF0(A, B, C)+D
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    rorxl \$23, $d,  $d					#ROTATELEFT(B,9);
    xorl $y0, $y2						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    xorl $e, $y3						#GG0(E,F,G)
    addl $y1, $y2						#FF0(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $f, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $_XFER+2*4(%rsp,$SRND,1), $y2	#FF0(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    addl $_XMM_SAVE+2*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    movl $y2, $b
    addl $y0, $y3						#GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $h, $h					#ROTATELEFT(F,19);
    rorxl \$23, $y3, $f
    rorxl \$15, $y3, $y1
    xorl $y3, $f
    xorl $y1, $f                       #P0(GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j])

    movl $b, $y1
    rorxl \$20, $b, $y0					#ROTATELEFT(A,12)
    xorl $c, $y1
    movl $f, $y3
    movl $y0, $y2						#ROTATELEFT(A,12)
    addl $f, $y0
    xorl $d, $y1						#FF0(A, B, C)
    addl 0($TBL), $y0
    add \$4, $TBL
    xorl $g, $y3
    addl $a, $y1						#FF0(A, B, C)+D
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    rorxl \$23, $c,  $c					#ROTATELEFT(B,9);
    xorl $y0, $y2						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    xorl $h, $y3						#GG0(E,F,G)
    addl $y1, $y2						#FF0(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $e, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $_XFER+3*4(%rsp,$SRND,1), $y2	#FF0(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    addl $_XMM_SAVE+3*4(%rsp,$SRND,1), $y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    movl $y2, $a
    addl $y0, $y3						#GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $g, $g					#ROTATELEFT(F,19);
    rorxl \$23, $y3, $e
    rorxl \$15, $y3, $y1
    xorl $y3, $e
    xorl $y1, $e                       #P0(GG0(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j])
___
}


sub SECOND_48_ROUNDS_WITHOUT_SCHED()
{   
$code.=<<___;
    movl $b, $y1
    movl $c, $y2
    rorxl \$20, $a, $y0					#ROTATELEFT(A,12)
    or $c, $y1						#(B|C)
    andl $b, $y2						#(B&C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $a, $y1						#A&(B|C)
    addl $e, $y0
    or $y2, $y1						#FF1(x,y,z)
    addl 0($TBL), $y0
    add \$4, $TBL
    movl $f, $y2
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $d, $y1						#FF1(A, B, C)+D
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $h, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    xorl $g, $y2
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $_XMM_SAVE+0*4(%rsp,$SRND,1),$y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    andl $e, $y2
    addl $_XFER+0*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    rorxl \$23, $b, $b					#ROTATELEFT(B,9);
    xorl $g, $y2
    movl $y3, $d
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $f, $f					#ROTATELEFT(F,19);
    rorxl \$23, $y0, $h
    rorxl \$15, $y0, $y3
    xorl $y0, $h
    xorl $y3, $h

    movl $a, $y1
    movl $b, $y2
    rorxl \$20, $d, $y0					#ROTATELEFT(A,12)
    or $b, $y1						#(B|C)
    andl $a, $y2						#(B&C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $d, $y1						#A&(B|C)
    addl $h, $y0
    or $y2, $y1						#FF1(x,y,z)
    addl 0($TBL), $y0
    add \$4, $TBL
    movl $e, $y2
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $c, $y1						#FF1(A, B, C)+D
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $g, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    xorl $f, $y2
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $_XMM_SAVE+1*4(%rsp,$SRND,1),$y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    andl $h, $y2
    addl $_XFER+1*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    rorxl \$23, $a, $a					#ROTATELEFT(B,9);
    xorl $f, $y2
    movl $y3, $c
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $e, $e					#ROTATELEFT(F,19);
    rorxl \$23, $y0, $g
    rorxl \$15, $y0, $y3
    xorl $y0, $g
    xorl $y3, $g

    movl $d, $y1
    movl $a, $y2
    rorxl \$20, $c, $y0					#ROTATELEFT(A,12)
    or $a, $y1						#(B|C)
    andl $d, $y2						#(B&C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $c, $y1						#A&(B|C)
    addl $g, $y0
    or $y2, $y1						#FF1(x,y,z)
    addl 0($TBL), $y0
    add \$4, $TBL
    movl $h, $y2
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $b, $y1						#FF1(A, B, C)+D
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $f, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    xorl $e, $y2
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $_XMM_SAVE+2*4(%rsp,$SRND,1),$y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    andl $g, $y2
    addl $_XFER+2*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    rorxl \$23, $d, $d					#ROTATELEFT(B,9);
    xorl $e, $y2
    movl $y3, $b
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $h, $h					#ROTATELEFT(F,19);
    rorxl \$23, $y0, $f
    rorxl \$15, $y0, $y3
    xorl $y0, $f
    xorl $y3, $f

    movl $c, $y1
    movl $d, $y2
    rorxl \$20, $b, $y0					#ROTATELEFT(A,12)
    or $d, $y1						#(B|C)
    andl $c, $y2						#(B&C)
    movl $y0, $y3						#ROTATELEFT(A,12)
    andl $b, $y1						#A&(B|C)
    addl $f, $y0
    or $y2, $y1						#FF1(x,y,z)
    addl 0($TBL), $y0
    add \$4, $TBL
    movl $g, $y2
    rorxl \$25, $y0, $y0				#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    addl $a, $y1						#FF1(A, B, C)+D
    xorl $y0, $y3						#ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $e, $y0						#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)
    xorl $h, $y2
    addl $y1, $y3						#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)
    addl $_XMM_SAVE+3*4(%rsp,$SRND,1),$y0	#H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    andl $f, $y2
    addl $_XFER+3*4(%rsp,$SRND,1), $y3	#FF1(A, B, C)+D+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7) ^ ROTATELEFT(A,12)+W'[j]
    rorxl \$23, $c, $c					#ROTATELEFT(B,9);
    xorl $h, $y2
    movl $y3, $a
    addl $y2, $y0						#GG1(E,F,G)+H+ROTATELEFT(ROTATELEFT(A,12) + E + k, 7)+W[j]
    rorxl \$13, $g, $g					#ROTATELEFT(F,19);
    rorxl \$23, $y0, $e
    rorxl \$15, $y0, $y3
    xorl $y0, $e
    xorl $y3, $e
___
}

$code.=<<___;

.globl  sm3_compress_avx2
.type   sm3_compress_avx2,\@function,3
.align  16
sm3_compress_avx2:

    push	%rbp
    push	%rbx
    push	%r12
    push	%r13
    push	%r14
    push	%r15

    mov %rsp, %rax
    sub \$`$STACK_SIZE`, %rsp
    and \$-32, %rsp
    mov %rax, $_RSP(%rsp)
    
    shl \$6, $NUM_BLKS
    jz  .done_hash

    lea -64($INP,$NUM_BLKS,1), $NUM_BLKS
    mov $NUM_BLKS, $_INP_END(%rsp)

    cmp $NUM_BLKS, $INP
    je  .only_one_block

    movl 0($CTX), $a
    movl 4($CTX), $b
    movl 8($CTX), $c
    movl 12($CTX), $d
    movl 16($CTX), $e
    movl 20($CTX), $f
    movl 24($CTX), $g
    movl 28($CTX), $h
    mov $CTX, $_CTX(%rsp)

.avx2_loop: # at each iteration works with one block (512 bit)

    vmovdqu 0*32($INP), $XTMP0
    vmovdqu 1*32($INP), $XTMP1
    vmovdqu 2*32($INP), $XTMP2
    vmovdqu 3*32($INP), $XTMP3

    vmovdqu PSHUFFLE_BYTE_FLIP_MASK(%rip), $BYTE_FLIP_MASK

    # Apply Byte Flip Mask: LE -> BE
    vpshufb $BYTE_FLIP_MASK, $XTMP0, $XTMP0
    vpshufb $BYTE_FLIP_MASK, $XTMP1, $XTMP1
    vpshufb $BYTE_FLIP_MASK, $XTMP2, $XTMP2
    vpshufb $BYTE_FLIP_MASK, $XTMP3, $XTMP3

    # Transpose data into high/low parts
    vperm2i128 \$0x20, $XTMP2, $XTMP0, %ymm4
    vperm2i128 \$0x31, $XTMP2, $XTMP0, %ymm5
    vperm2i128 \$0x20, $XTMP3, $XTMP1, %ymm6
    vperm2i128 \$0x31, $XTMP3, $XTMP1, %ymm7

    lea K256(%rip), $TBL

.last_block_enter:
    add \$64, $INP
    mov $INP, $_INP(%rsp)
    xor $SRND, $SRND

    vpxor %ymm4, %ymm5, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm4, $_XMM_SAVE(%rsp,$SRND)
___
    &FIRST_16_ROUNDS_AND_SCHED("%ymm4", "%ymm5", "%ymm6", "%ymm7");
$code.=<<___;
    add \$32, $SRND
    vpxor %ymm5, %ymm6, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm5, $_XMM_SAVE(%rsp,$SRND)
___
    &FIRST_16_ROUNDS_AND_SCHED("%ymm5", "%ymm6", "%ymm7", "%ymm4");
$code.=<<___;
    add \$32, $SRND
    vpxor %ymm6, %ymm7, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm6, $_XMM_SAVE(%rsp,$SRND)
___
    &FIRST_16_ROUNDS_AND_SCHED("%ymm6", "%ymm7", "%ymm4", "%ymm5");
$code.=<<___;
    add \$32, $SRND
    vpxor %ymm7, %ymm4, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm7, $_XMM_SAVE(%rsp,$SRND)
___
    &FIRST_16_ROUNDS_AND_SCHED("%ymm7", "%ymm4", "%ymm5", "%ymm6");
$code.=<<___;
    add	\$32, $SRND
    vpxor %ymm4, %ymm5, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm4, $_XMM_SAVE(%rsp,$SRND)
___
    &SECOND_36_ROUNDS_AND_SCHED("%ymm4", "%ymm5", "%ymm6", "%ymm7");
$code.=<<___;
    add	\$32, $SRND
    vpxor %ymm5, %ymm6, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm5, $_XMM_SAVE(%rsp,$SRND)
___
    &SECOND_36_ROUNDS_AND_SCHED("%ymm5", "%ymm6", "%ymm7", "%ymm4");
$code.=<<___;
    add	\$32, $SRND
    vpxor %ymm6, %ymm7, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm6, $_XMM_SAVE(%rsp,$SRND)
___
    &SECOND_36_ROUNDS_AND_SCHED("%ymm6", "%ymm7", "%ymm4", "%ymm5");
$code.=<<___;
    add	\$32, $SRND
    vpxor %ymm7, %ymm4, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm7, $_XMM_SAVE(%rsp,$SRND)
___
    &SECOND_36_ROUNDS_AND_SCHED("%ymm7", "%ymm4", "%ymm5", "%ymm6");
$code.=<<___;
    add	\$32, $SRND
    vpxor %ymm4, %ymm5, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm4, $_XMM_SAVE(%rsp,$SRND)
___
    &SECOND_36_ROUNDS_AND_SCHED("%ymm4", "%ymm5", "%ymm6", "%ymm7");
$code.=<<___;
    add	\$32, $SRND
    vpxor %ymm5, %ymm6, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm5, $_XMM_SAVE(%rsp,$SRND)
___
    &SECOND_36_ROUNDS_AND_SCHED("%ymm5", "%ymm6", "%ymm7", "%ymm4");
$code.=<<___;
    add	\$32, $SRND
    vpxor %ymm6, %ymm7, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm6, $_XMM_SAVE(%rsp,$SRND)
___
    &SECOND_36_ROUNDS_AND_SCHED("%ymm6", "%ymm7", "%ymm4", "%ymm5");
$code.=<<___;
    add	\$32, $SRND
    vpxor %ymm7, %ymm4, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm7, $_XMM_SAVE(%rsp,$SRND)
___
    &SECOND_36_ROUNDS_AND_SCHED("%ymm7", "%ymm4", "%ymm5", "%ymm6");
$code.=<<___;
    add	\$32, $SRND
    vpxor %ymm4, %ymm5, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm4, $_XMM_SAVE(%rsp,$SRND)
___
    &SECOND_36_ROUNDS_AND_SCHED("%ymm4", "%ymm5", "%ymm6", "%ymm7");
$code.=<<___;
    add \$32, $SRND
    vpxor %ymm5, %ymm6, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm5, $_XMM_SAVE(%rsp,$SRND)
___
    &THIRD_12_ROUNDS_AND_SCHED("%ymm5", "%ymm6", "%ymm7", "%ymm4");
$code.=<<___;
    add \$32, $SRND
    vpxor %ymm6, %ymm7, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm6, $_XMM_SAVE(%rsp,$SRND)
___
    &THIRD_12_ROUNDS_AND_SCHED("%ymm6", "%ymm7", "%ymm4", "%ymm5");
$code.=<<___;
    add \$32, $SRND
    vpxor %ymm7, %ymm4, $XFER
    vmovdqu $XFER, $_XFER(%rsp,$SRND)
    vmovdqu %ymm7, $_XMM_SAVE(%rsp,$SRND)
___
    &THIRD_12_ROUNDS_AND_SCHED("%ymm7", "%ymm4", "%ymm5", "%ymm6");
$code.=<<___;

    mov $_CTX(%rsp), $CTX
    mov $_INP(%rsp), $INP

    xorl    $a, 0($CTX)
    xorl    $b, 4($CTX)
    xorl    $c, 8($CTX)
    xorl    $d, 12($CTX)
    xorl    $e, 16($CTX)
    xorl    $f, 20($CTX)
    xorl    $g, 24($CTX)
    xorl    $h, 28($CTX)

    cmp $_INP_END(%rsp), $INP
    ja .done_hash

    lea K256(%rip), $TBL
    movl    0($CTX), $a
    movl    4($CTX), $b
    movl    8($CTX), $c
    movl    12($CTX), $d
    movl    16($CTX), $e
    movl    20($CTX), $f
    movl    24($CTX), $g
    movl    28($CTX), $h
    xor $SRND, $SRND

    add \$16, $SRND
___
    &FIRST_16_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &FIRST_16_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &FIRST_16_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &FIRST_16_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;
    add \$32, $SRND
___
    &SECOND_48_ROUNDS_WITHOUT_SCHED();
$code.=<<___;

    mov $_CTX(%rsp), $CTX
    mov $_INP(%rsp), $INP
    add	\$64, $INP

    xorl    $a, 0($CTX)
    xorl    $b, 4($CTX)
    xorl    $c, 8($CTX)
    xorl    $d, 12($CTX)
    xorl    $e, 16($CTX)
    xorl    $f, 20($CTX)
    xorl    $g, 24($CTX)
    xorl    $h, 28($CTX)
    movl    0($CTX), $a
    movl    4($CTX), $b
    movl    8($CTX), $c
    movl    12($CTX), $d
    movl    16($CTX), $e
    movl    20($CTX), $f
    movl    24($CTX), $g
    movl    28($CTX), $h

    cmp $_INP_END(%rsp), $INP
    jb  .avx2_loop
    ja  .done_hash

.do_last_block:
    vmovdqu 0*16($INP), $XWORD0
    vmovdqu 1*16($INP), $XWORD1
    vmovdqu 2*16($INP), $XWORD2
    vmovdqu 3*16($INP), $XWORD3

    vmovdqu PSHUFFLE_BYTE_FLIP_MASK(%rip), $BYTE_FLIP_MASK

    vpshufb $X_BYTE_FLIP_MASK, $XWORD0, $XWORD0
    vpshufb $X_BYTE_FLIP_MASK, $XWORD1, $XWORD1
    vpshufb $X_BYTE_FLIP_MASK, $XWORD2, $XWORD2
    vpshufb $X_BYTE_FLIP_MASK, $XWORD3, $XWORD3

    lea K256(%rip), $TBL
    jmp .last_block_enter

.only_one_block:
    movl    4*0($CTX), $a
    movl    4*1($CTX), $b
    movl    4*2($CTX), $c
    movl    4*3($CTX), $d
    movl    4*4($CTX), $e
    movl    4*5($CTX), $f
    movl    4*6($CTX), $g
    movl    4*7($CTX), $h

    mov $CTX, $_CTX(%rsp)
    jmp .do_last_block

.done_hash:
    vzeroupper
    mov $_RSP(%rsp), %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
.size   sm3_compress_avx2,.-sm3_compress_avx2
___


$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT or die "error closing STDOUT: $!";