//
//  DesEncrypt.h
//  AesEncrypt
//
//  Created by yinlinlin on 2018/3/31.
//  Copyright © 2018年 EL. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DesEncrypt : NSObject

+ (NSString *)stringByDesECBEncrypt:(NSString *)string key:(NSString *)key;
+ (NSString *)stringByDesECBDecrypt:(NSString *)string key:(NSString *)key;
+ (NSString *)stringBy3DesECBEncrypt:(NSString *)string key:(NSString *)key;
+ (NSString *)stringBy3DesECBDecrypt:(NSString *)string key:(NSString *)key;

+(NSString *)stringByDesCBCEncrypt:(NSString *)string key:(NSString *)key iv:(NSString *)iv;
+(NSString *)stringByDesCBCDecrypt:(NSString *)string key:(NSString *)key iv:(NSString *)iv;
+(NSString *)stringBy3DesCBCEncrypt:(NSString *)string key:(NSString *)key iv:(NSString *)iv;
+(NSString *)stringBy3DesCBCDecrypt:(NSString *)string key:(NSString *)key iv:(NSString *)iv;

@end
