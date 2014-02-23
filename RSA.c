/***************************************************************************************************************
name:		RSA.C
author:		yuxiang
date:       2011.9.21
note：		本程序使用的是RSA 512位加密算法。默认为密钥N长度为64个字节，以字节为单元存储；
			若有变动，请及时修改RSA.h中的NSIZE与UNIT_BITS；以及各个函数参数数据类型(若UNIT_BITS改动)。
			
*************************************************************************************************************/

#include<stdio.h>
#include<string.h>
#include "RSA.h"

/******************比较运算***************************************/
/*byte1>byte2,1;byte1<byt2,-1;byte1=byte2 0;*/

int Large_Compare(U8*largebyte1,U8*largebyte2)
{	
	U8 i=0;
	U8 len=NSIZE;
    i=len;
    largebyte1+=len;                    //将指针移至大数的高位字节
    largebyte2+=len;
	while (i--)
		if (*--largebyte1 - *--largebyte2)
			return (int) *largebyte1 - (int) *largebyte2;
	return 0;

}
/****************复制运算***b-->a***a=b**************************/
void Large_Copy(U8*a,U8*b)
{
	U16 i = NSIZE;
	while (i--)
		*a++ = *b++;
}

/****************左移运算******a =a*2=a+a ***********************/
U16 Large_Slift(U8*a)
{
	 U16 c = 0, i = NSIZE;
	while (i--) 
	{
		c |= (U16)* a << 1;
		*a++ = c;
		c = (c >>UNIT_BITS)&1;
	}
	if((c&0xffff)!=0)
	{
		printf("Large_Slift:最高位有进位！\n");
	}
	return c;
}
/****************减法运算******a=a-b*****************************/
U16 Large_Sub(U8*a,U8*b)
{
	U16 c = 0, i = NSIZE;
	while (i--) 
	{
		c = *a - *(b++) - c;
		*a++ = c;
		c = (c >> UNIT_BITS) &1;          //当低位有借位的时候，c=0x0001
	}
	if(c&0xffff!=0)
	{
			printf("Large_Sub:最高位有借位!\n");
	}
    return c;
}

/****************加法运算****** a=a+b ***************************/
U16 Large_Add(U8*a,U8*b)
{
	U16 c = 0, i = NSIZE;
	while (i--) 
	{
		c = *(b++) + *a + c;
		*a++ = c;
		c >>= UNIT_BITS;
	} 
	if(c&0xffff!=0)
	{
    	printf("Large_Add:最高位有进位！\n");
	}
    return c;
}
/**************************乘模运算******a=a*b mod N***************/
void Mul_Mod(U8*a,U8*b,U8*Np)
{
	U16 k =UNIT_BITS;
	U16 i;
	U8 temp[NSIZE];
	memset(temp,0,NSIZE);
	for(i=NSIZE;i>0;i--)
	{
		for(k=UNIT_BITS;k>0;k--)
		{
		  Large_Slift(temp);                 //temp=temp+temp;
		 if(Large_Compare(temp,Np)>0)        //temp>N时	      
			   Large_Sub(temp,Np);           // temp=temp-N;
		 if((a[i-1]&(1<<(k-1)))!=0)          //对应位的值为1
			  Large_Add(temp,b);             //temp=temp+b;
		 if(Large_Compare(temp,Np)>0)        //temp>N时
			  Large_Sub(temp,Np);            // temp=temp-N;
		}
	}
    Large_Copy(a,temp);                      //结果值赋予a
	
}
/*******************************幂模运算****************************/
void Rec_Power_Mod(U8*p_output,U8*p_input,U8*ped_byte,U8*pN,U8 ed_len)
{
U16 k=UNIT_BITS;                  
U16 i=0;							         //i存储了d所占的字节数
U8  dectemp[64];
memset(dectemp,0,64);
if(ped_byte[ed_len-1]&(1<<7))				 //D的最高字节的最高位是否为1
	Large_Copy(dectemp,p_input);		     //p_dectemp=p_input
else
	dectemp[0]=0x01;					     //dectemp=1;
for(i=ed_len;i>0;i--)
	for(k=UNIT_BITS;k>0;k--)
	{
		Mul_Mod(dectemp,dectemp,pN);         //dectemp=(dectemp*dectemp)mod (pN);
		if((ped_byte[i-1]&(1<<(k-1)))!=0)    //对应位的值为1
	    Mul_Mod(dectemp,p_input,pN);	     //dectemp=(dectemp*p_input)mod(pN);
	}

 Large_Copy(p_output,dectemp);   

}



/****************************************RSA解密函数**********************************
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


int Decrypt(U8*p_decrypted,U8* p_crypted,U8*p_dbyte,U8*p_Nbyte,U16 pdec_len, U16 pec_len,U16 pd_len,U16 pN_len  )
{
U8 Np[NSIZE],EC[NSIZE],DEC[NSIZE];            //NSIZE指密钥N的字节长度
U16 dec_len=pdec_len;                         //记录DEC,EC，d，N数组的长度
U16 ec_len =pec_len;
U16 d_len  =pd_len;
U16 N_len  =pN_len;
if(p_decrypted==NULL||p_crypted==NULL||p_dbyte==NULL||p_Nbyte==NULL||dec_len<=0||ec_len<=0||d_len<=0||N_len<=0)
{
	printf("待解密参数有误!\n");             //参数校验
	return -1;

}
if(ec_len>NSIZE)                             //判断密文是否过长（应不大于N的字节长度）
{
	printf("待解密字符串过长！\n");
    return -2;
}
memset(Np,0,NSIZE);                          // 填充数组
memcpy(Np,p_Nbyte,N_len);					 // 使参与运算的数组均为NSIZE个字节（与密钥N的长度相同）
memset(EC,0,NSIZE);							 // D数组为指数不能扩展
memcpy(EC,p_crypted,ec_len);
memset(DEC,0,NSIZE);
memcpy(DEC,p_decrypted,dec_len);
Rec_Power_Mod(DEC,EC,p_dbyte,Np,d_len);
memcpy(p_decrypted,DEC,dec_len);
return 0;
}



/*****************************************RSA加密函数************************************
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

int Ecrypt(U8*p_ecrypting,U8* p_original,U8*p_ebyte,U8*p_Nbyte,U16 pecing_len, U16 poriginal_len,U16 pe_len,U16 pN_len )
{
U8 Np[NSIZE],EC[NSIZE],OR[NSIZE];
U16 ecing_len=pecing_len;
U16 original_len =poriginal_len;
U16 e_len  =pe_len;
U16 N_len  =pN_len;
if(p_ecrypting==NULL||p_original==NULL||p_ebyte==NULL||p_Nbyte==NULL||ecing_len<=0||original_len<=0||e_len<=0||N_len<=0)
{
	printf("待解密参数有误!\n");             //参数校验
	return -1;

}
if(original_len>NSIZE)                       //判断待加密的明文是否过长（应不大于N的字节长度）
{
	printf("待加密字符串过长！\n");
    return -2;
}
memset(Np,0,NSIZE);                          //填充数组
memcpy(Np,p_Nbyte,N_len);
memset(OR,0,NSIZE);
memcpy(OR,p_original,original_len);
memset(EC,0,NSIZE);
memcpy(EC,p_ecrypting,ecing_len);
Rec_Power_Mod(EC,OR,p_ebyte,Np,e_len);
memcpy(p_ecrypting,EC,ecing_len);
return 0;
}






















