//
//  SecurityUtil.h
//  Smile
//
//  Created by apple on 15/8/25.
//  Copyright (c) 2015年 Weconex. All rights reserved.
//

#import "SecurityUtil.h"
#import "GTMBase64.h"
#import "NSData+AES.h"

#define Iv          @""//@"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"//@"0392039203920300" //偏移量,可自行修改
//#define KEY         @"1234567890abcdef"//@"smkldospdosldaaa" //key，可自行修改

@implementation SecurityUtil

#pragma mark - base64
+ (NSString*)encodeBase64String:(NSString * )input { 
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES]; 
    data = [GTMBase64 encodeData:data]; 
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
	return base64String;
    
}

+ (NSString*)decodeBase64String:(NSString * )input { 
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES]; 
    data = [GTMBase64 decodeData:data]; 
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
	return base64String;
} 

+ (NSString*)encodeBase64Data:(NSData *)data {
	data = [GTMBase64 encodeData:data]; 
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
	return base64String;
}

+ (NSString*)decodeBase64Data:(NSData *)data {
	data = [GTMBase64 decodeData:data]; 
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
	return base64String;
}

#pragma mark - AES加密
//将string转成带密码的data
+(NSString*)encryptAESString:(NSString*)string Key:(NSString*)key
{
    //将nsstring转化为nsdata
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    //使用密码对nsdata进行加密
    NSData *encryptedData = [data AES128EncryptWithKey:key gIv:Iv];
    //返回进行base64进行转码的加密字符串
    return [self encodeBase64Data:encryptedData];
}

#pragma mark - AES解密
//将带密码的data转成string
+(NSString*)decryptAESString:(NSString *)string Key:(NSString*)key
{
    //base64解密
    NSData *decodeBase64Data=[GTMBase64 decodeString:string];
    //使用密码对data进行解密
    NSData *decryData = [decodeBase64Data AES128DecryptWithKey:key gIv:Iv];
    
    //    NSData* xmlData = [string dataUsingEncoding:NSUTF8StringEncoding];
    //    NSData *decryData = [xmlData AES128DecryptWithKey:KEY gIv:Iv];
    
    //将解了密码的nsdata转化为nsstring
    NSString *str = [[NSString alloc] initWithData:decryData encoding:NSUTF8StringEncoding];
    return str;
}

+ (NSData *)encryptAESData:(NSData *)data Key:(NSString *)key {
    NSData *aesEncryptData = [data AES128EncryptWithKey:key gIv:Iv];
    return [GTMBase64 encodeData:aesEncryptData];
}

+ (NSData *)decryptAESData:(NSData *)data Key:(NSString *)key {
    NSData *base64Data = [GTMBase64 decodeData:data];
    NSData *aesDecryptData = [base64Data AES128DecryptWithKey:key gIv:Iv];
    return aesDecryptData;
}

//URLEncode
+ (NSString*)encodeString:(NSString*)unencodedString {
    NSString *encodedString = (NSString *)
    CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault,
                                                              (CFStringRef)unencodedString,
                                                              NULL,
                                                              (CFStringRef)@"!*'();:@&=+$,/?%#[]",
                                                              kCFStringEncodingUTF8));
    
    return encodedString;
}

//URLDEcode
+ (NSString *)decodeString:(NSString*)encodedString {
    NSString *decodedString  = ( NSString *)CFBridgingRelease(CFURLCreateStringByReplacingPercentEscapesUsingEncoding(NULL,
                                                                                                                      (__bridge CFStringRef)encodedString,
                                                                                                                      CFSTR(""),
                                                                                                                      CFStringConvertNSStringEncodingToEncoding(NSUTF8StringEncoding)));
    return decodedString;
}

@end
