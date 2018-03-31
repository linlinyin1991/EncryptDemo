//
//  DesEncrypt.m
//  AesEncrypt
//
//  Created by yinlinlin on 2018/3/31.
//  Copyright © 2018年 EL. All rights reserved.
//

#import "DesEncrypt.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation DesEncrypt


+ (NSString *)stringByDesECBEncrypt:(NSString *)string key:(NSString *)key {
    NSData *result = [self dataByDesECB:[string dataUsingEncoding:NSUTF8StringEncoding] key:key mode:kCCEncrypt];
    return [self stringByBase64EncryptData:result];
}

+ (NSString *)stringByDesECBDecrypt:(NSString *)string key:(NSString *)key {
    NSData *data = [self dataByBase64DecryptString:string];
    NSData* result = [self dataByDesECB:data key:key mode:kCCDecrypt];
    NSString *resultStr = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    if (resultStr.length == 0) {return @"";}
    return resultStr;
}

+ (NSString *)stringBy3DesECBEncrypt:(NSString *)string key:(NSString *)key {
    NSData *result = [self dataBy3DesECB:[string dataUsingEncoding:NSUTF8StringEncoding] key:key mode:kCCEncrypt];
    return [self stringByBase64EncryptData:result];
}

+ (NSString *)stringBy3DesECBDecrypt:(NSString *)string key:(NSString *)key {
    NSData *data = [self dataByBase64DecryptString:string];
    NSData* result = [self dataBy3DesECB:data key:key mode:kCCDecrypt];
    NSString *resultStr = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    if (resultStr.length == 0) {return @"";}
    return resultStr;
}


+(NSString *)stringByDesCBCEncrypt:(NSString *)string key:(NSString *)key iv:(NSString *)iv {
    NSData *result = [self dataByDesCBC:[string dataUsingEncoding:NSUTF8StringEncoding] key:key mode:kCCEncrypt iv:iv];
    return [self stringByBase64EncryptData:result];
}
+(NSString *)stringByDesCBCDecrypt:(NSString *)string key:(NSString *)key iv:(NSString *)iv {
    NSData *data = [self dataByBase64DecryptString:string];
    NSData* result = [self dataByDesCBC:data key:key mode:kCCDecrypt iv:iv];
    NSString *resultStr = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    if (resultStr.length == 0) {return @"";}
    return resultStr;
}
+(NSString *)stringBy3DesCBCEncrypt:(NSString *)string key:(NSString *)key iv:(NSString *)iv {
    NSData *result = [self dataBy3DesCBC:[string dataUsingEncoding:NSUTF8StringEncoding] key:key mode:kCCEncrypt iv:iv];
    return [self stringByBase64EncryptData:result];
}
+(NSString *)stringBy3DesCBCDecrypt:(NSString *)string key:(NSString *)key iv:(NSString *)iv {
    NSData *data = [self dataByBase64DecryptString:string];
    NSData* result = [self dataBy3DesCBC:data key:key mode:kCCDecrypt iv:iv];
    NSString *resultStr = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    if (resultStr.length == 0) {return @"";}
    return resultStr;
}

#pragma mark - ECB模式
+(NSData *)dataByDesECB:(NSData *)data key:(NSString *)key mode:(CCOperation)operation {
    char keyPtr[kCCKeySizeDES + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = data.length;
    
    size_t bufferSize = dataLength + kCCBlockSizeDES;
    void * buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,//ECB模式
                                          keyPtr,
                                          kCCKeySizeDES,
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

+(NSData *)dataBy3DesECB:(NSData *)data key:(NSString *)key mode:(CCOperation)operation {
    char keyPtr[kCCKeySize3DES + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = data.length;
    
    size_t bufferSize = dataLength + kCCBlockSize3DES;
    void * buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithm3DES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,//ECB模式
                                          keyPtr,
                                          kCCKeySize3DES,
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

#pragma mark CBC mode
+(NSData *)dataByDesCBC:(NSData *)data key:(NSString *)key mode:(CCOperation)operation iv:(NSString *)iv{
    char keyPtr[kCCKeySizeDES + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = data.length;
    size_t bufferSize = dataLength + kCCBlockSizeDES;
    void * buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    NSString * initIv = iv;
    char ivPtr[kCCBlockSizeAES128+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [initIv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySizeDES,
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

+(NSData *)dataBy3DesCBC:(NSData *)data key:(NSString *)key mode:(CCOperation)operation iv:(NSString *)iv {
    char keyPtr[kCCKeySize3DES + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = data.length;
    
    size_t bufferSize = dataLength + kCCBlockSize3DES;
    void * buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    NSString * initIv = iv;
    char ivPtr[kCCBlockSizeAES128+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [initIv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithm3DES,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySize3DES,
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
