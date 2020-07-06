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

# if (`$CC -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
#         =~ /([2-9]\.[0-9]+)/) { # todo : GNU assembler version (/([2-9]\.[0-9]+)/)
#     $avx = ($1>=2.19) + ($1>=2.22);
#     $addx = ($1>=2.23);
# }

# if (!$addx && $win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
#         `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)/) {
#     $avx = ($1>=2.09) + ($1>=2.10);
#     $addx = ($1>=2.10);
# }

# if (!$addx && $win64 && ($flavour =~ /masm/ || $ENV{ASM} =~ /ml64/) &&
#         `ml64 2>&1` =~ /Version ([0-9]+)\./) {
#     $avx = ($1>=10) + ($1>=11);
#     $addx = ($1>=12);
# }

# if (!$addx && `$ENV{CC} -v 2>&1` =~ /((?:^clang|LLVM) version|.*based on LLVM) ([3-9])\.([0-9]+)/) {
#     my $ver = $2 + $3/100.0;	# 3.1->3.01, 3.10->3.10
#     $avx = ($ver>=3.0) + ($ver>=3.01);
#     $addx = ($ver>=3.03);
# }

$avx = 2;
$addx = 1;

$code.=<<___;
.text
.hidden	cpu_info
#.comm	cpu_info,16,4

.LOne:
.long 1,1,1,1,1,1,1,1

.extern	cpu_info
___

{

my ($a0,$a1,$a2,$a3)=map("%r$_",(8..11));
my ($t0,$t1,$t2,$t3,$t4,$t5)=("%rax","%rdx","%r14","%r12","%r13","%r15");
my ($r_ptr,$a_ptr,$b_ptr,$p_ptr)=("%rdi","%rsi","%rdx","%rcx");

$code.=<<___;

# # void fp_set(uint64_t *res, uint64_t *a);
# .globl	fp_set
# .type	fp_set,\@function,2
# .align	32
# fp_set:
#     movdqa	0x00($a_ptr), %xmm0
#     movdqa	0x10($a_ptr), %xmm1
#     movdqa	%xmm0, 0x00($r_ptr)
#     movdqa	%xmm1, 0x10($r_ptr)

#     ret
# .size	fp_set,.-fp_set

# void fp_div_by_2(uint64_t res[4], uint64_t a[4], uint64_t p[4]);
.globl	fp_div_by_2
.type	fp_div_by_2,\@function,3
.align	32
fp_div_by_2:
    push	%r12
    push	%r13
    push	%r14
    push	%r15

    mov	8*0($a_ptr), $a0
    mov	8*1($a_ptr), $a1
    mov	8*2($a_ptr), $a2
     mov	$a0, $t0
    mov	8*3($a_ptr), $a3

     mov	$a1, $t5
    xor	$t4, $t4
    add	8*0($b_ptr), $a0
     mov	$a2, $t2
    adc	8*1($b_ptr), $a1
    adc	8*2($b_ptr), $a2
     mov	$a3, $t3
    adc	8*3($b_ptr), $a3
    adc	\$0, $t4
    xor	$b_ptr, $b_ptr		# borrow $b_ptr
    test	\$1, $t0

    cmovz	$t0, $a0
    cmovz	$t5, $a1
    cmovz	$t2, $a2
    cmovz	$t3, $a3
    cmovz	$b_ptr, $t4

    mov	$a1, $t0		# a0:a3>>1
    shr	\$1, $a0
    shl	\$63, $t0
    mov	$a2, $t5
    shr	\$1, $a1
    or	$t0, $a0
    shl	\$63, $t5
    mov	$a3, $t2
    shr	\$1, $a2
    or	$t5, $a1
    shl	\$63, $t2
    shr	\$1, $a3
    shl	\$63, $t4
    or	$t2, $a2
    or	$t4, $a3

    mov	$a0, 8*0($r_ptr)
    mov	$a1, 8*1($r_ptr)
    mov	$a2, 8*2($r_ptr)
    mov	$a3, 8*3($r_ptr)

    pop	%r15
    pop	%r14
    pop	%r13
    pop	%r12
    ret
.size	fp_div_by_2,.-fp_div_by_2

################################################################################
# void fp_add(uint64_t res[4], uint64_t a[4], uint64_t b[4], uint64_t p[4]);
.globl	fp_add
.type	fp_add,\@function,4
.align	32
fp_add:
    push	%r12
    push	%r13
    push	%r14

    mov	8*0($a_ptr), $a0
    xor	$t4, $t4
    mov	8*1($a_ptr), $a1
    mov	8*2($a_ptr), $a2
    mov	8*3($a_ptr), $a3

    add	8*0($b_ptr), $a0
    adc	8*1($b_ptr), $a1
     mov	$a0, $t0
    adc	8*2($b_ptr), $a2
    adc	8*3($b_ptr), $a3
     mov	$a1, $t1
    adc	\$0, $t4

    sub	8*0($p_ptr), $a0
     mov	$a2, $t2
    sbb	8*1($p_ptr), $a1
    sbb	8*2($p_ptr), $a2
     mov	$a3, $t3
    sbb	8*3($p_ptr), $a3
    sbb	\$0, $t4

    cmovc	$t0, $a0
    cmovc	$t1, $a1
    mov	$a0, 8*0($r_ptr)
    cmovc	$t2, $a2
    mov	$a1, 8*1($r_ptr)
    cmovc	$t3, $a3
    mov	$a2, 8*2($r_ptr)
    mov	$a3, 8*3($r_ptr)

    pop %r14
    pop %r13
    pop %r12
    ret
.size	fp_add,.-fp_add

################################################################################
# void fp_sub(uint64_t res[4], uint64_t a[4], uint64_t b[4], uint8_t p[64]);
.globl	fp_sub
.type	fp_sub,\@function,4
.align	32
fp_sub:
    push	%r12
    push	%r13
    push	%r14

    mov	8*0($a_ptr), $a0
    xor	$t4, $t4
    mov	8*1($a_ptr), $a1
    mov	8*2($a_ptr), $a2
    mov	8*3($a_ptr), $a3


    sub	8*0($b_ptr), $a0
    sbb	8*1($b_ptr), $a1
     mov	$a0, $t0
    sbb	8*2($b_ptr), $a2
    sbb	8*3($b_ptr), $a3
     mov	$a1, $t1
    sbb	\$0, $t4

    add	8*0($p_ptr), $a0
     mov	$a2, $t2
    adc	8*1($p_ptr), $a1
    adc	8*2($p_ptr), $a2
     mov	$a3, $t3
    adc	8*3($p_ptr), $a3
    test	$t4, $t4

    cmovz	$t0, $a0
    cmovz	$t1, $a1
    mov	$a0, 8*0($r_ptr)
    cmovz	$t2, $a2
    mov	$a1, 8*1($r_ptr)
    cmovz	$t3, $a3
    mov	$a2, 8*2($r_ptr)
    mov	$a3, 8*3($r_ptr)

    pop %r14
    pop %r13
    pop %r12
    ret
.size	fp_sub,.-fp_sub

################################################################################
# void fp_neg(uint64_t res[4], uint64_t a[4], uint64_t p[4]);
.globl	fp_neg
.type	fp_neg,\@function,3
.align	32
fp_neg:

    mov	8*0($b_ptr), $a0
    mov	8*1($b_ptr), $a1
    mov	8*2($b_ptr), $a2
    mov	8*3($b_ptr), $a3

    sub	8*0($a_ptr), $a0
    sbb	8*1($a_ptr), $a1
    sbb	8*2($a_ptr), $a2
    sbb	8*3($a_ptr), $a3

    mov	$a0, 8*0($r_ptr)
    mov	$a1, 8*1($r_ptr)
    mov	$a2, 8*2($r_ptr)
    mov	$a3, 8*3($r_ptr)

    ret
.size	fp_neg,.-fp_neg

################################################################################
# void fp_double(uint64_t res[4], uint64_t a[4], uint64_t p[4]);
.globl	fp_double
.type	fp_double,\@function,3
.align	32
fp_double:
    push	%r12
    push	%r13
    push	%r14
    push	%r15

    mov	8*0($a_ptr), $a0
    xor	$t4,$t4
    mov	8*1($a_ptr), $a1
    add	$a0, $a0		# a0:a3+a0:a3
    mov	8*2($a_ptr), $a2
    adc	$a1, $a1
    mov	8*3($a_ptr), $a3
     mov	$a0, $t0
    adc	$a2, $a2
    adc	$a3, $a3
     mov	$a1, $t5
    adc	\$0, $t4

    sub	8*0($b_ptr), $a0
     mov	$a2, $t2
    sbb	8*1($b_ptr), $a1
    sbb	8*2($b_ptr), $a2
     mov	$a3, $t3
    sbb	8*3($b_ptr), $a3
    sbb	\$0, $t4

    cmovc	$t0, $a0
    cmovc	$t5, $a1
    mov	$a0, 8*0($r_ptr)
    cmovc	$t2, $a2
    mov	$a1, 8*1($r_ptr)
    cmovc	$t3, $a3
    mov	$a2, 8*2($r_ptr)
    mov	$a3, 8*3($r_ptr)

    pop %r15
    pop %r14
    pop	%r13
    pop	%r12
    ret
.size	fp_double,.-fp_double

################################################################################
# void fp_triple(uint64_t res[4], uint64_t a[4], uint64_t p[4]);
.globl	fp_triple
.type	fp_triple,\@function,3
.align	32
fp_triple:
    push	%r12
    push	%r13
    push	%r14
    push	%r15

    mov	8*0($a_ptr), $a0
    xor	$t4, $t4
    mov	8*1($a_ptr), $a1
    add	$a0, $a0		# a0:a3+a0:a3
    mov	8*2($a_ptr), $a2
    adc	$a1, $a1
    mov	8*3($a_ptr), $a3
     mov	$a0, $t0
    adc	$a2, $a2
    adc	$a3, $a3
     mov	$a1, $t5
    adc	\$0, $t4

    sub	8*0($b_ptr), $a0
     mov	$a2, $t2
    sbb	8*1($b_ptr), $a1
    sbb	8*2($b_ptr), $a2
     mov	$a3, $t3
    sbb	8*3($b_ptr), $a3
    sbb	\$0, $t4

    cmovc	$t0, $a0
    cmovc	$t5, $a1
    cmovc	$t2, $a2
    cmovc	$t3, $a3

    xor	$t4, $t4
    add	8*0($a_ptr), $a0	# a0:a3+=a_ptr[0:3]
    adc	8*1($a_ptr), $a1
     mov	$a0, $t0
    adc	8*2($a_ptr), $a2
    adc	8*3($a_ptr), $a3
     mov	$a1, $t5
    adc	\$0, $t4

    sub	8*0($b_ptr), $a0
     mov	$a2, $t2
    sbb	8*1($b_ptr), $a1
    sbb	8*2($b_ptr), $a2
     mov	$a3, $t3
    sbb	8*3($b_ptr), $a3
    sbb	\$0, $t4

    cmovc	$t0, $a0
    cmovc	$t5, $a1
    mov	$a0, 8*0($r_ptr)
    cmovc	$t2, $a2
    mov	$a1, 8*1($r_ptr)
    cmovc	$t3, $a3
    mov	$a2, 8*2($r_ptr)
    mov	$a3, 8*3($r_ptr)

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    ret
.size	fp_triple,.-fp_triple
___
}

{
my ($val,$in_t,$index)=$win64?("%rcx","%rdx","%r8d"):("%rdi","%rsi","%edx");
my ($ONE,$INDEX,$Ra,$Rb,$Rc,$Rd,$Re,$Rf)=map("%xmm$_",(0..7));
my ($M0,$T0a,$T0b,$T0c,$T0d,$T0e,$T0f,$TMP0)=map("%xmm$_",(8..15));

$code.=<<___;
################################################################################
# void G1_scatter_w5(uint64_t *val, uint64_t *in_t, int index);
.globl	G1_scatter_w5
.type	G1_scatter_w5,\@abi-omnipotent
.align	32
G1_scatter_w5:
    lea	-3($index,$index,2), $index
    movdqa	0x00($in_t), %xmm0
    shl	\$5, $index
    movdqa	0x10($in_t), %xmm1
    movdqa	0x20($in_t), %xmm2
    movdqa	0x30($in_t), %xmm3
    movdqa	0x40($in_t), %xmm4
    movdqa	0x50($in_t), %xmm5
    movdqa	%xmm0, 0x00($val,$index)
    movdqa	%xmm1, 0x10($val,$index)
    movdqa	%xmm2, 0x20($val,$index)
    movdqa	%xmm3, 0x30($val,$index)
    movdqa	%xmm4, 0x40($val,$index)
    movdqa	%xmm5, 0x50($val,$index)

    ret
.size	G1_scatter_w5,.-G1_scatter_w5

################################################################################
# void G1_gather_w5(uint64_t *val, uint64_t *in_t, int index);
.globl	G1_gather_w5
.type	G1_gather_w5,\@abi-omnipotent
.align	32
G1_gather_w5:
___
$code.=<<___	if ($win64);
    lea	-0x88(%rsp), %rax
.LSEH_begin_G1_gather_w5:
    .byte	0x48,0x8d,0x60,0xe0		#lea	-0x20(%rax), %rsp
    .byte	0x0f,0x29,0x70,0xe0		#movaps	%xmm6, -0x20(%rax)
    .byte	0x0f,0x29,0x78,0xf0		#movaps	%xmm7, -0x10(%rax)
    .byte	0x44,0x0f,0x29,0x00		#movaps	%xmm8, 0(%rax)
    .byte	0x44,0x0f,0x29,0x48,0x10	#movaps	%xmm9, 0x10(%rax)
    .byte	0x44,0x0f,0x29,0x50,0x20	#movaps	%xmm10, 0x20(%rax)
    .byte	0x44,0x0f,0x29,0x58,0x30	#movaps	%xmm11, 0x30(%rax)
    .byte	0x44,0x0f,0x29,0x60,0x40	#movaps	%xmm12, 0x40(%rax)
    .byte	0x44,0x0f,0x29,0x68,0x50	#movaps	%xmm13, 0x50(%rax)
    .byte	0x44,0x0f,0x29,0x70,0x60	#movaps	%xmm14, 0x60(%rax)
    .byte	0x44,0x0f,0x29,0x78,0x70	#movaps	%xmm15, 0x70(%rax)
___
$code.=<<___;
    movdqa	.LOne(%rip), $ONE
    movd	$index, $INDEX

    pxor	$Ra, $Ra
    pxor	$Rb, $Rb
    pxor	$Rc, $Rc
    pxor	$Rd, $Rd
    pxor	$Re, $Re
    pxor	$Rf, $Rf

    movdqa	$ONE, $M0
    pshufd	\$0, $INDEX, $INDEX

    mov	\$16, %rax
.Lselect_loop_sse_g1_w5:

    movdqa	$M0, $TMP0
    paddd	$ONE, $M0
    pcmpeqd $INDEX, $TMP0

    movdqa	16*0($in_t), $T0a
    movdqa	16*1($in_t), $T0b
    movdqa	16*2($in_t), $T0c
    movdqa	16*3($in_t), $T0d
    movdqa	16*4($in_t), $T0e
    movdqa	16*5($in_t), $T0f
    lea 16*6($in_t), $in_t

    pand	$TMP0, $T0a
    pand	$TMP0, $T0b
    por	$T0a, $Ra
    pand	$TMP0, $T0c
    por	$T0b, $Rb
    pand	$TMP0, $T0d
    por	$T0c, $Rc
    pand	$TMP0, $T0e
    por	$T0d, $Rd
    pand	$TMP0, $T0f
    por	$T0e, $Re
    por	$T0f, $Rf

    dec	%rax
    jnz	.Lselect_loop_sse_g1_w5

    movdqu	$Ra, 16*0($val)
    movdqu	$Rb, 16*1($val)
    movdqu	$Rc, 16*2($val)
    movdqu	$Rd, 16*3($val)
    movdqu	$Re, 16*4($val)
    movdqu	$Rf, 16*5($val)
___
$code.=<<___	if ($win64);
    movaps	(%rsp), %xmm6
    movaps	0x10(%rsp), %xmm7
    movaps	0x20(%rsp), %xmm8
    movaps	0x30(%rsp), %xmm9
    movaps	0x40(%rsp), %xmm10
    movaps	0x50(%rsp), %xmm11
    movaps	0x60(%rsp), %xmm12
    movaps	0x70(%rsp), %xmm13
    movaps	0x80(%rsp), %xmm14
    movaps	0x90(%rsp), %xmm15
    lea	0xa8(%rsp), %rsp
.LSEH_end_G1_gather_w5:
___
$code.=<<___;
    ret
.size	G1_gather_w5,.-G1_gather_w5

################################################################################
# void G2_scatter_w5(uint64_t *val, uint64_t *in_t, int index);
.globl	G2_scatter_w5
.type	G2_scatter_w5,\@abi-omnipotent
.align	32
G2_scatter_w5:
    lea	-3($index,$index,2), $index
    movdqa	0x00($in_t), %xmm0
    shl	\$6, $index
    movdqa	0x10($in_t), %xmm1
    movdqa	0x20($in_t), %xmm2
    movdqa	0x30($in_t), %xmm3
    movdqa	0x40($in_t), %xmm4
    movdqa	0x50($in_t), %xmm5
    movdqa	0x60($in_t), %xmm6
    movdqa	0x70($in_t), %xmm7
    movdqa	0x80($in_t), %xmm8
    movdqa	0x90($in_t), %xmm9
    movdqa	0xa0($in_t), %xmm10
    movdqa	0xb0($in_t), %xmm11
    movdqa	%xmm0, 0x00($val,$index)
    movdqa	%xmm1, 0x10($val,$index)
    movdqa	%xmm2, 0x20($val,$index)
    movdqa	%xmm3, 0x30($val,$index)
    movdqa	%xmm4, 0x40($val,$index)
    movdqa	%xmm5, 0x50($val,$index)
    movdqa	%xmm6, 0x60($val,$index)
    movdqa	%xmm7, 0x70($val,$index)
    movdqa	%xmm8, 0x80($val,$index)
    movdqa	%xmm9, 0x90($val,$index)
    movdqa	%xmm10, 0xa0($val,$index)
    movdqa	%xmm11, 0xb0($val,$index)

    ret
.size	G1_scatter_w5,.-G1_scatter_w5


################################################################################
# void G2_gather_w5(uint64_t *val, uint64_t *in_t, int index);
.globl	G2_gather_w5
.type	G2_gather_w5,\@abi-omnipotent
.align	32
G2_gather_w5:
___
$code.=<<___	if ($win64);
    lea	-0x88(%rsp), %rax
.LSEH_begin_G2_gather_w5:
    .byte	0x48,0x8d,0x60,0xe0		#lea	-0x20(%rax), %rsp
    .byte	0x0f,0x29,0x70,0xe0		#movaps	%xmm6, -0x20(%rax)
    .byte	0x0f,0x29,0x78,0xf0		#movaps	%xmm7, -0x10(%rax)
    .byte	0x44,0x0f,0x29,0x00		#movaps	%xmm8, 0(%rax)
    .byte	0x44,0x0f,0x29,0x48,0x10	#movaps	%xmm9, 0x10(%rax)
    .byte	0x44,0x0f,0x29,0x50,0x20	#movaps	%xmm10, 0x20(%rax)
    .byte	0x44,0x0f,0x29,0x58,0x30	#movaps	%xmm11, 0x30(%rax)
    .byte	0x44,0x0f,0x29,0x60,0x40	#movaps	%xmm12, 0x40(%rax)
    .byte	0x44,0x0f,0x29,0x68,0x50	#movaps	%xmm13, 0x50(%rax)
    .byte	0x44,0x0f,0x29,0x70,0x60	#movaps	%xmm14, 0x60(%rax)
    .byte	0x44,0x0f,0x29,0x78,0x70	#movaps	%xmm15, 0x70(%rax)
___
$code.=<<___;
    movdqa	.LOne(%rip), $ONE
    movd	$index, $INDEX
    pshufd	\$0, $INDEX, $INDEX
# first part

    pxor	$Ra, $Ra
    pxor	$Rb, $Rb
    pxor	$Rc, $Rc
    pxor	$Rd, $Rd
    pxor	$Re, $Re
    pxor	$Rf, $Rf

    movdqa	$ONE, $M0

    mov	\$16, %rax
.Lselect_loop_sse_g2_w5_1:

    movdqa	$M0, $TMP0
    paddd	$ONE, $M0
    pcmpeqd $INDEX, $TMP0

    movdqa	16*0($in_t), $T0a
    movdqa	16*1($in_t), $T0b
    movdqa	16*2($in_t), $T0c
    movdqa	16*3($in_t), $T0d
    movdqa	16*4($in_t), $T0e
    movdqa	16*5($in_t), $T0f
    lea 16*12($in_t), $in_t

    pand	$TMP0, $T0a
    pand	$TMP0, $T0b
    por	$T0a, $Ra
    pand	$TMP0, $T0c
    por	$T0b, $Rb
    pand	$TMP0, $T0d
    por	$T0c, $Rc
    pand	$TMP0, $T0e
    por	$T0d, $Rd
    pand	$TMP0, $T0f
    por	$T0e, $Re
    por	$T0f, $Rf

    dec	%rax
    jnz	.Lselect_loop_sse_g2_w5_1

    movdqu	$Ra, 16*0($val)
    movdqu	$Rb, 16*1($val)
    movdqu	$Rc, 16*2($val)
    movdqu	$Rd, 16*3($val)
    movdqu	$Re, 16*4($val)
    movdqu	$Rf, 16*5($val)

# second part
    lea -16*192($in_t), $in_t
    pxor	$Ra, $Ra
    pxor	$Rb, $Rb
    pxor	$Rc, $Rc
    pxor	$Rd, $Rd
    pxor	$Re, $Re
    pxor	$Rf, $Rf

    movdqa	$ONE, $M0

    mov	\$16, %rax
.Lselect_loop_sse_g2_w5_2:

    movdqa	$M0, $TMP0
    paddd	$ONE, $M0
    pcmpeqd $INDEX, $TMP0

    movdqa	16*6($in_t), $T0a
    movdqa	16*7($in_t), $T0b
    movdqa	16*8($in_t), $T0c
    movdqa	16*9($in_t), $T0d
    movdqa	16*10($in_t), $T0e
    movdqa	16*11($in_t), $T0f
    lea 16*12($in_t), $in_t

    pand	$TMP0, $T0a
    pand	$TMP0, $T0b
    por	$T0a, $Ra
    pand	$TMP0, $T0c
    por	$T0b, $Rb
    pand	$TMP0, $T0d
    por	$T0c, $Rc
    pand	$TMP0, $T0e
    por	$T0d, $Rd
    pand	$TMP0, $T0f
    por	$T0e, $Re
    por	$T0f, $Rf

    dec	%rax
    jnz	.Lselect_loop_sse_g2_w5_2

    movdqu	$Ra, 16*6($val)
    movdqu	$Rb, 16*7($val)
    movdqu	$Rc, 16*8($val)
    movdqu	$Rd, 16*9($val)
    movdqu	$Re, 16*10($val)
    movdqu	$Rf, 16*11($val)
___
$code.=<<___	if ($win64);
    movaps	(%rsp), %xmm6
    movaps	0x10(%rsp), %xmm7
    movaps	0x20(%rsp), %xmm8
    movaps	0x30(%rsp), %xmm9
    movaps	0x40(%rsp), %xmm10
    movaps	0x50(%rsp), %xmm11
    movaps	0x60(%rsp), %xmm12
    movaps	0x70(%rsp), %xmm13
    movaps	0x80(%rsp), %xmm14
    movaps	0x90(%rsp), %xmm15
    lea	0xa8(%rsp), %rsp
.LSEH_end_G2_gather_w5:
___
$code.=<<___;
    ret
.size	G2_gather_w5,.-G2_gather_w5

################################################################################
# void GT_scatter_w4(uint64_t *val, uint64_t *in_t, int index);
.globl	GT_scatter_w4
.type	GT_scatter_w4,\@abi-omnipotent
.align	32
GT_scatter_w4:
    lea	-3($index,$index,2), $index
    movdqa	0x00($in_t), %xmm0
    shl	\$7, $index
    movdqa	0x10($in_t), %xmm1
    movdqa	0x20($in_t), %xmm2
    movdqa	0x30($in_t), %xmm3
    movdqa	0x40($in_t), %xmm4
    movdqa	0x50($in_t), %xmm5
    movdqa	0x60($in_t), %xmm6
    movdqa	0x70($in_t), %xmm7
    movdqa	0x80($in_t), %xmm8
    movdqa	0x90($in_t), %xmm9
    movdqa	0xa0($in_t), %xmm10
    movdqa	0xb0($in_t), %xmm11
    movdqa	%xmm0, 0x00($val,$index)
    movdqa	%xmm1, 0x10($val,$index)
    movdqa	%xmm2, 0x20($val,$index)
    movdqa	%xmm3, 0x30($val,$index)
    movdqa	%xmm4, 0x40($val,$index)
    movdqa	%xmm5, 0x50($val,$index)
    movdqa	%xmm6, 0x60($val,$index)
    movdqa	%xmm7, 0x70($val,$index)
    movdqa	%xmm8, 0x80($val,$index)
    movdqa	%xmm9, 0x90($val,$index)
    movdqa	%xmm10, 0xa0($val,$index)
    movdqa	%xmm11, 0xb0($val,$index)
    movdqa	0xc0($in_t), %xmm0
    movdqa	0xd0($in_t), %xmm1
    movdqa	0xe0($in_t), %xmm2
    movdqa	0xf0($in_t), %xmm3
    movdqa	0x100($in_t), %xmm4
    movdqa	0x110($in_t), %xmm5
    movdqa	0x120($in_t), %xmm6
    movdqa	0x130($in_t), %xmm7
    movdqa	0x140($in_t), %xmm8
    movdqa	0x150($in_t), %xmm9
    movdqa	0x160($in_t), %xmm10
    movdqa	0x170($in_t), %xmm11
    movdqa	%xmm0, 0xc0($val,$index)
    movdqa	%xmm1, 0xd0($val,$index)
    movdqa	%xmm2, 0xe0($val,$index)
    movdqa	%xmm3, 0xf0($val,$index)
    movdqa	%xmm4, 0x100($val,$index)
    movdqa	%xmm5, 0x110($val,$index)
    movdqa	%xmm6, 0x120($val,$index)
    movdqa	%xmm7, 0x130($val,$index)
    movdqa	%xmm8, 0x140($val,$index)
    movdqa	%xmm9, 0x150($val,$index)
    movdqa	%xmm10, 0x160($val,$index)
    movdqa	%xmm11, 0x170($val,$index)

    ret
.size	GT_scatter_w4,.-GT_scatter_w4

################################################################################
# void GT_gather_w4(uint64_t *val, uint64_t *in_t, int index);
.globl	GT_gather_w4
.type	GT_gather_w4,\@abi-omnipotent
.align	32
GT_gather_w4:
___
$code.=<<___	if ($win64);
    lea	-0x88(%rsp), %rax
.LSEH_begin_GT_gather_w4:
    .byte	0x48,0x8d,0x60,0xe0		#lea	-0x20(%rax), %rsp
    .byte	0x0f,0x29,0x70,0xe0		#movaps	%xmm6, -0x20(%rax)
    .byte	0x0f,0x29,0x78,0xf0		#movaps	%xmm7, -0x10(%rax)
    .byte	0x44,0x0f,0x29,0x00		#movaps	%xmm8, 0(%rax)
    .byte	0x44,0x0f,0x29,0x48,0x10	#movaps	%xmm9, 0x10(%rax)
    .byte	0x44,0x0f,0x29,0x50,0x20	#movaps	%xmm10, 0x20(%rax)
    .byte	0x44,0x0f,0x29,0x58,0x30	#movaps	%xmm11, 0x30(%rax)
    .byte	0x44,0x0f,0x29,0x60,0x40	#movaps	%xmm12, 0x40(%rax)
    .byte	0x44,0x0f,0x29,0x68,0x50	#movaps	%xmm13, 0x50(%rax)
    .byte	0x44,0x0f,0x29,0x70,0x60	#movaps	%xmm14, 0x60(%rax)
    .byte	0x44,0x0f,0x29,0x78,0x70	#movaps	%xmm15, 0x70(%rax)
___
$code.=<<___;
    movdqa	.LOne(%rip), $ONE
    movd	$index, $INDEX
    pshufd	\$0, $INDEX, $INDEX
# first part

    pxor	$Ra, $Ra
    pxor	$Rb, $Rb
    pxor	$Rc, $Rc
    pxor	$Rd, $Rd
    pxor	$Re, $Re
    pxor	$Rf, $Rf

    movdqa	$ONE, $M0

    mov	\$16, %rax
.Lselect_loop_sse_gt_w4_1:

    movdqa	$M0, $TMP0
    paddd	$ONE, $M0
    pcmpeqd $INDEX, $TMP0

    movdqa	16*0($in_t), $T0a
    movdqa	16*1($in_t), $T0b
    movdqa	16*2($in_t), $T0c
    movdqa	16*3($in_t), $T0d
    movdqa	16*4($in_t), $T0e
    movdqa	16*5($in_t), $T0f
    lea 16*24($in_t), $in_t

    pand	$TMP0, $T0a
    pand	$TMP0, $T0b
    por	$T0a, $Ra
    pand	$TMP0, $T0c
    por	$T0b, $Rb
    pand	$TMP0, $T0d
    por	$T0c, $Rc
    pand	$TMP0, $T0e
    por	$T0d, $Rd
    pand	$TMP0, $T0f
    por	$T0e, $Re
    por	$T0f, $Rf

    dec	%rax
    jnz	.Lselect_loop_sse_gt_w4_1

    movdqu	$Ra, 16*0($val)
    movdqu	$Rb, 16*1($val)
    movdqu	$Rc, 16*2($val)
    movdqu	$Rd, 16*3($val)
    movdqu	$Re, 16*4($val)
    movdqu	$Rf, 16*5($val)

# second part
    lea -16*384($in_t), $in_t
    pxor	$Ra, $Ra
    pxor	$Rb, $Rb
    pxor	$Rc, $Rc
    pxor	$Rd, $Rd
    pxor	$Re, $Re
    pxor	$Rf, $Rf

    movdqa	$ONE, $M0

    mov	\$16, %rax
.Lselect_loop_sse_gt_w4_2:

    movdqa	$M0, $TMP0
    paddd	$ONE, $M0
    pcmpeqd $INDEX, $TMP0

    movdqa	16*6($in_t), $T0a
    movdqa	16*7($in_t), $T0b
    movdqa	16*8($in_t), $T0c
    movdqa	16*9($in_t), $T0d
    movdqa	16*10($in_t), $T0e
    movdqa	16*11($in_t), $T0f
    lea 16*24($in_t), $in_t

    pand	$TMP0, $T0a
    pand	$TMP0, $T0b
    por	$T0a, $Ra
    pand	$TMP0, $T0c
    por	$T0b, $Rb
    pand	$TMP0, $T0d
    por	$T0c, $Rc
    pand	$TMP0, $T0e
    por	$T0d, $Rd
    pand	$TMP0, $T0f
    por	$T0e, $Re
    por	$T0f, $Rf

    dec	%rax
    jnz	.Lselect_loop_sse_gt_w4_2

    movdqu	$Ra, 16*6($val)
    movdqu	$Rb, 16*7($val)
    movdqu	$Rc, 16*8($val)
    movdqu	$Rd, 16*9($val)
    movdqu	$Re, 16*10($val)
    movdqu	$Rf, 16*11($val)

# third part
    lea -16*384($in_t), $in_t
    pxor	$Ra, $Ra
    pxor	$Rb, $Rb
    pxor	$Rc, $Rc
    pxor	$Rd, $Rd
    pxor	$Re, $Re
    pxor	$Rf, $Rf

    movdqa	$ONE, $M0

    mov	\$16, %rax
.Lselect_loop_sse_gt_w4_3:

    movdqa	$M0, $TMP0
    paddd	$ONE, $M0
    pcmpeqd $INDEX, $TMP0

    movdqa	16*12($in_t), $T0a
    movdqa	16*13($in_t), $T0b
    movdqa	16*14($in_t), $T0c
    movdqa	16*15($in_t), $T0d
    movdqa	16*16($in_t), $T0e
    movdqa	16*17($in_t), $T0f
    lea 16*24($in_t), $in_t

    pand	$TMP0, $T0a
    pand	$TMP0, $T0b
    por	$T0a, $Ra
    pand	$TMP0, $T0c
    por	$T0b, $Rb
    pand	$TMP0, $T0d
    por	$T0c, $Rc
    pand	$TMP0, $T0e
    por	$T0d, $Rd
    pand	$TMP0, $T0f
    por	$T0e, $Re
    por	$T0f, $Rf

    dec	%rax
    jnz	.Lselect_loop_sse_gt_w4_3

    movdqu	$Ra, 16*12($val)
    movdqu	$Rb, 16*13($val)
    movdqu	$Rc, 16*14($val)
    movdqu	$Rd, 16*15($val)
    movdqu	$Re, 16*16($val)
    movdqu	$Rf, 16*17($val)

# fourth part
    lea -16*384($in_t), $in_t
    pxor	$Ra, $Ra
    pxor	$Rb, $Rb
    pxor	$Rc, $Rc
    pxor	$Rd, $Rd
    pxor	$Re, $Re
    pxor	$Rf, $Rf

    movdqa	$ONE, $M0

    mov	\$16, %rax
.Lselect_loop_sse_gt_w4_4:

    movdqa	$M0, $TMP0
    paddd	$ONE, $M0
    pcmpeqd $INDEX, $TMP0

    movdqa	16*18($in_t), $T0a
    movdqa	16*19($in_t), $T0b
    movdqa	16*20($in_t), $T0c
    movdqa	16*21($in_t), $T0d
    movdqa	16*22($in_t), $T0e
    movdqa	16*23($in_t), $T0f
    lea 16*24($in_t), $in_t

    pand	$TMP0, $T0a
    pand	$TMP0, $T0b
    por	$T0a, $Ra
    pand	$TMP0, $T0c
    por	$T0b, $Rb
    pand	$TMP0, $T0d
    por	$T0c, $Rc
    pand	$TMP0, $T0e
    por	$T0d, $Rd
    pand	$TMP0, $T0f
    por	$T0e, $Re
    por	$T0f, $Rf

    dec	%rax
    jnz	.Lselect_loop_sse_gt_w4_4

    movdqu	$Ra, 16*18($val)
    movdqu	$Rb, 16*19($val)
    movdqu	$Rc, 16*20($val)
    movdqu	$Rd, 16*21($val)
    movdqu	$Re, 16*22($val)
    movdqu	$Rf, 16*23($val)

___
$code.=<<___	if ($win64);
    movaps	(%rsp), %xmm6
    movaps	0x10(%rsp), %xmm7
    movaps	0x20(%rsp), %xmm8
    movaps	0x30(%rsp), %xmm9
    movaps	0x40(%rsp), %xmm10
    movaps	0x50(%rsp), %xmm11
    movaps	0x60(%rsp), %xmm12
    movaps	0x70(%rsp), %xmm13
    movaps	0x80(%rsp), %xmm14
    movaps	0x90(%rsp), %xmm15
    lea	0xa8(%rsp), %rsp
.LSEH_end_GT_gather_w4:
___
$code.=<<___;
    ret
.size	GT_gather_w4,.-GT_gather_w4

___
}

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT or die "error closing STDOUT: $!";
