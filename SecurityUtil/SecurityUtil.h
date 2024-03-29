//
//  SecurityUtil.h
//  Smile
//
//  Created by apple on 15/8/25.
//  Copyright (c) 2015年 Weconex. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SecurityUtil : NSObject 

#pragma mark - base64
+ (NSString *)encodeBase64String:(NSString *)input;
+ (NSString *)decodeBase64String:(NSString *)input;

+ (NSString *)encodeBase64Data:(NSData *)data;
+ (NSString *)decodeBase64Data:(NSData *)data;

#pragma mark - AES加密
//将string转成带密码的data
+ (NSString *)encryptAESString:(NSString *)string Key:(NSString *)key;
+ (NSString *)encryptAES256String:(NSString *)string Key:(NSString *)key;
//将带密码的data转成string
+ (NSString *)decryptAESString:(NSString *)string Key:(NSString *)key;
+ (NSString *)decryptAES256String:(NSString *)string Key:(NSString *)key;

+ (NSData *)encryptAESData:(NSData *)data Key:(NSString *)key;
+ (NSData *)decryptAESData:(NSData *)data Key:(NSString *)key;

//URLEncode
+ (NSString *)encodeString:(NSString *)unencodedString;
//URLDEcode
+ (NSString *)decodeString:(NSString *)encodedString;

@end
