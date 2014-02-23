/***************************************************************************************************************
name:		RSA.C
author:		yuxiang
date:       2011.9.21
note：		本程序使用的是RSA 512位加密算法。默认为密钥N长度为64个字节，以字节为单元存储；
			若有变动，请及时修改RSA.h中的NSIZE与UNIT_BITS；以及各个函数参数数据类型(若UNIT_BITS改动)。
			
*************************************************************************************************************/


#ifndef __RSA_H__
#define __RSA_H__


#ifndef	U8
typedef unsigned char  U8;
#endif
#ifndef	U16
typedef unsigned short U16;
#endif
#ifndef	U32
typedef unsigned int   U32;
#endif

#ifndef NSIZE
#define NSIZE  64      //密钥N存储的字节长度，若有变动 及时修改
#endif
#define UNIT_BITS  8   // 密钥N存储方式，现以字节为单元存储，若有变动及时修改

/****************************************RSA解密函数Decrypt***********************************
U8*p_decrypted 	解密后的明文字符数组           （输出）；
U8* p_crypted 	待解密的密文字符数组           （输入）；
U8*p_dbyte     	解密密钥d                       (输入)；
U8*p_Nbyte     	密钥数组N                      （输入）；
U16 pdec_len    存储明文的数组p_decrypted的长度（输入）；
U16 pec_len     待解密数组p_crypted的长度      （输入）；
U16 pd_len      数组p_dbyte的长度              （输入）；
U16 pN_len      数组p_Nbyte的长度              （输入）；
返回值： 
 -2            	错误: 参数错误，指针为空或数组长度不大于零；
 -1            	错误：密文长度pec_len大于N的长度；
  0            	成功调用；
功能：	解密RSA加密后的密文。
注意：	在RSA加密解密中，被加密或解密的字符串长度，要求不大于N的长度。
**************************************************************************************/

int Decrypt(U8*p_decrypted,U8* p_crypted,U8*p_dbyte,U8*p_Nbyte,U16 pdec_len, U16 pec_len,U16 pd_len,U16 pN_len  );


/****************************************RSA加密函数Ecrypt***********************************
参数：
U8* p_ecrypting 	 加密后的密文字符数组            （输出）；
U8* p_original  	 待加密的明文字符数组            （输入）；
U8* p_ebyte     	 加密密钥e          			 （输入）；
U8*p_Nbyte      	 密钥数组N        				 （输入）；
U16 pecing_len  	 密文数组p_decrypted的长度		 （输入）；
U16 poriginal_len  	 明文数组p_crypted的长度         （输入）；
U16 pe_len           数组p_ebyte的长度               （输入）；
U16 pN_len           数组p_Nbyte的长度               （输入）；
返回值： 
 -2            错误: 参数错误，指针为空或数组长度不大于零；
 -1            错误：密文长度pec_len大于N的长度；
  0            成功调用；
功能：用RSA算法加密明文，生成密文。
注意：在RSA加密解密中，被加密或解密的字符串长度，要求不大于N的长度。
**************************************************************************************/
int Ecrypt(U8*p_ecrypting,U8* p_original,U8*p_ebyte,U8*p_Nbyte,U16 pecing_len, U16 poriginal_len,U16 pe_len,U16 pN_len );

#endif



