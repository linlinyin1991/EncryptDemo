//
//  BKJKEncrypt.h
//  ELNetwork_Example
//
//  Created by ElaineYin on 2018/3/28.
//  Copyright © 2018年 ElaineYin. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AesEncrypt : NSObject

#pragma mark - AES加解密

+ (NSString *)stringByAes256Encrypt:(NSString *)string key:(NSString *)key;
+ (NSString *)stringByAes256Decrypt:(NSString *)string key:(NSString *)key;

+(NSString *)stringByAes128CBCEncrypt:(NSString *)string key:(NSString *)key;
+(NSString *)stringByAes128CBCDecrypt:(NSString *)string key:(NSString *)key;

@end
