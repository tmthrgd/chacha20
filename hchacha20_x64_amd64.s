// Created by hchacha20_x64.pl - DO NOT EDIT
// perl hchacha20_x64.pl golang-no-avx hchacha20_x64_amd64.s

// +build amd64,!gccgo,!appengine

// This code was translated into a form compatible with 6a from the public
// domain sources in SUPERCOP: http://bench.cr.yp.to/supercop.html

#include "textflag.h"

TEXT ·hchacha_20_x64(SB),$0-24
	MOVQ	key+0(FP),DI
	MOVQ	nonce+8(FP),SI
	MOVQ	out+16(FP),DX

	MOVQ	$20,CX
	MOVQ	$3684054920433006693,AX
	MOVQ	$7719281312240119090,R8
	MOVD	AX,X0
	MOVD	R8,X4
	PUNPCKLQDQ	X4,X0
	// MOVDQU	0(DI),X1
	BYTE $0xf3; BYTE $0x0f; BYTE $0x6f; BYTE $0x0f
	// MOVDQU	16(DI),X2
	BYTE $0xf3; BYTE $0x0f; BYTE $0x6f; BYTE $0x57; BYTE $0x10
	// MOVDQU	0(SI),X3
	BYTE $0xf3; BYTE $0x0f; BYTE $0x6f; BYTE $0x1e
hchacha_sse2_mainloop:
	PADDD	X1,X0
	PXOR	X0,X3
	PSHUFLW	$177,X3,X3
	PSHUFHW	$177,X3,X3
	PADDD	X3,X2
	PXOR	X2,X1
	// MOVDQA	X1,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x6f; BYTE $0xe1
	// PSLLD	$12,X1
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xf1; BYTE $0x0c
	// PSRLD	$20,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xd4; BYTE $0x14
	PXOR	X4,X1
	PADDD	X1,X0
	PXOR	X0,X3
	// MOVDQA	X3,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x6f; BYTE $0xe3
	// PSLLD	$8,X3
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xf3; BYTE $0x08
	// PSRLD	$24,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xd4; BYTE $0x18
	PSHUFD	$147,X0,X0
	PXOR	X4,X3
	PADDD	X3,X2
	PSHUFD	$78,X3,X3
	PXOR	X2,X1
	PSHUFD	$57,X2,X2
	// MOVDQA	X1,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x6f; BYTE $0xe1
	// PSLLD	$7,X1
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xf1; BYTE $0x07
	// PSRLD	$25,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xd4; BYTE $0x19
	PXOR	X4,X1
	SUBQ	$2,CX
	PADDD	X1,X0
	PXOR	X0,X3
	PSHUFLW	$177,X3,X3
	PSHUFHW	$177,X3,X3
	PADDD	X3,X2
	PXOR	X2,X1
	// MOVDQA	X1,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x6f; BYTE $0xe1
	// PSLLD	$12,X1
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xf1; BYTE $0x0c
	// PSRLD	$20,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xd4; BYTE $0x14
	PXOR	X4,X1
	PADDD	X1,X0
	PXOR	X0,X3
	// MOVDQA	X3,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x6f; BYTE $0xe3
	// PSLLD	$8,X3
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xf3; BYTE $0x08
	// PSRLD	$24,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xd4; BYTE $0x18
	PSHUFD	$57,X0,X0
	PXOR	X4,X3
	PADDD	X3,X2
	PSHUFD	$78,X3,X3
	PXOR	X2,X1
	PSHUFD	$147,X2,X2
	// MOVDQA	X1,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x6f; BYTE $0xe1
	// PSLLD	$7,X1
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xf1; BYTE $0x07
	// PSRLD	$25,X4
	BYTE $0x66; BYTE $0x0f; BYTE $0x72; BYTE $0xd4; BYTE $0x19
	PXOR	X4,X1
	JA	hchacha_sse2_mainloop
	// MOVDQU	X0,0(DX)
	BYTE $0xf3; BYTE $0x0f; BYTE $0x7f; BYTE $0x02
	// MOVDQU	X3,16(DX)
	BYTE $0xf3; BYTE $0x0f; BYTE $0x7f; BYTE $0x5a; BYTE $0x10
	RET
