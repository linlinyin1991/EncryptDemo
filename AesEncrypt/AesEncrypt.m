//
//  BKJKEncrypt.m
//  ELNetwork_Example
//
//  Created by ElaineYin on 2018/3/28.
//  Copyright © 2018年 ElaineYin. All rights reserved.
//

#import "AesEncrypt.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#ifndef kAESIV /* optional initialization vector */
#define kAESIV @"8841054029634287"
#endif

@implementation AesEncrypt

#pragma mark - AES256 ECB 加解密

+ (NSString *)stringByAes256Encrypt:(NSString *)string key:(NSString *)key {
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSData *result = [self dataByAes256ECB:data key:key mode:kCCEncrypt];
    if (result.length == 0) {return @"";}
    NSString *resultStr = nil;
    NSData * aesData = [NSData dataWithBytes:(const void *)result.bytes length:result.length];
    resultStr = [self stringByBase64EncryptData:aesData];
    if (resultStr.length == 0) {return @"";}
    return resultStr;
}
+ (NSString *)stringByAes256Decrypt:(NSString *)string key:(NSString *)key {
    NSData *data = [self dataByBase64DecryptString:string];
    NSData* result = [self dataByAes256ECB:data key:key mode:kCCDecrypt];
    NSString * resultStr = nil;
    if (result.length == 0) {return @"";}
    resultStr = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    if (resultStr.length == 0) {return @"";}
    return resultStr;
}

+(NSData *)dataByAes256ECB:(NSData *)data key:(NSString *)key mode:(CCOperation)operation {
    char keyPtr[kCCKeySizeAES256 + 1];//选择aes256加密，所以key长度应该是kCCKeySizeAES256，32位
    bzero(keyPtr, sizeof(keyPtr));//数组全部填充0
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];//秘钥key转成cString
    
    NSUInteger dataLength = data.length;
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    
    void * buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,//ECB模式
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          NULL,//选择ECB模式，不需要向量
                                          data.bytes,
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        NSData * result = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
        return result;
    }
    free(buffer);
    return nil;
}

#pragma mark - AES128 CBC 加解密
+(NSString *)stringByAes128CBCEncrypt:(NSString *)string key:(NSString *)key {
    return [self stringByAes128CBC:string key:key mode:kCCEncrypt iv:kAESIV];
}

+(NSString *)stringByAes128CBCDecrypt:(NSString *)string key:(NSString *)key{
    return [self stringByAes128CBC:string key:key mode:kCCDecrypt iv:kAESIV];
}

+(NSString *)stringByAes128CBC:(NSString *)string key:(NSString *)key mode:(CCOperation)operation iv:(NSString *)iv {
    if (operation == kCCEncrypt) {
        NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
        NSData *result = [self dataByAes:data key:key mode:kCCEncrypt iv:iv];
        if (result.length == 0) {return @"";}
        NSString *resultStr = nil;
        NSData * aesData = [NSData dataWithBytes:(const void *)result.bytes length:result.length];
        resultStr = [self stringByBase64EncryptData:aesData];
        if (resultStr.length == 0) {return @"";}
        return resultStr;
    }else{
        NSData *data = [self dataByBase64DecryptString:string];
        NSData* result = [self dataByAes:data key:key mode:kCCDecrypt iv:iv];
        NSString * resultStr = nil;
        if (result.length == 0) {return @"";}
        resultStr = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
        if (resultStr.length == 0) {return @"";}
        return resultStr;
    }
}

+(NSData *)dataByAes:(NSData *)data key:(NSString *)key mode:(CCOperation)operation iv:(NSString *)iv {
    char keyPtr[kCCKeySizeAES128 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = data.length;
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void * buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    
    NSString * initIv = iv;
    char ivPtr[kCCBlockSizeAES128+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [initIv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySizeAES128,
                                          ivPtr,
                                          data.bytes,
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        NSData * result = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
        return result;
    }
    free(buffer);
    return nil;
}



+(NSString *)stringByBase64EncryptData:(NSData *)data {
    NSData *tmpData = [data base64EncodedDataWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSString *ret = [[NSString alloc] initWithData:tmpData encoding:NSUTF8StringEncoding];
    return ret;
}

+(NSData *)dataByBase64DecryptString:(NSString *)string {
    return [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

@end
