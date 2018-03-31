//
//  ViewController.m
//  AesEncrypt
//
//  Created by ElaineYin on 2018/3/29.
//  Copyright © 2018年 EL. All rights reserved.
//

#import "ViewController.h"
#import "AesEncrypt.h"
#import "DesEncrypt.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
//    [self AesTest];
    [self DesTest];
}

- (void)AesTest {
    //AesEncrypt提供了128CBC和256EBC两种方法，需要其他aes加密的话按需直接替换加解密方法kCCKeySizeAES*** 这个部分就可以
    NSString * string = @"Hello, my name is ElaineYin, you can call me MuMu too!";
    
    NSString *aes256Key = @"Hello1I2am3Elai4Hello1I2am3Elai4";
    NSString *encryptString = [AesEncrypt stringByAes256Encrypt:string key:aes256Key];
    NSString *decryptString = [AesEncrypt stringByAes256Decrypt:encryptString key:aes256Key];
    NSLog(@"Aes256ECB：\n加密：%@\n解密：%@\n",encryptString,decryptString);
    
    //CBC模式需要设置向量，AesEncrypt.m文件里面设置了默认的kAESIV，自己按需要修改
    NSString *aes128Key = @"ello1I2am3Elai4H";
    encryptString = [AesEncrypt stringByAes128CBCEncrypt:string key:aes128Key];
    decryptString = [AesEncrypt stringByAes128CBCDecrypt:encryptString key:aes128Key];
    NSLog(@"Aes128CBC：\n加密：%@\n解密：%@\n",encryptString,decryptString);
}

- (void)DesTest {
    NSString * string = @"Hello, my name is ElaineYin, you can call me MuMu too!";
    
    NSString *desIV = @"1234h879";
    
    NSString *desKey = @"ijkn1234";
    NSString *encryptString = [DesEncrypt stringByDesECBEncrypt:string key:desKey];
    NSString *decryptString = [DesEncrypt stringByDesECBDecrypt:encryptString key:desKey];
    NSLog(@"Des ECB：\n加密：%@\n解密：%@\n",encryptString,decryptString);
    encryptString = [DesEncrypt stringByDesCBCEncrypt:string key:desKey iv:desIV];
    decryptString = [DesEncrypt stringByDesCBCDecrypt:encryptString key:desKey iv:desIV];
    NSLog(@"Des CBC：\n加密：%@\n解密：%@\n",encryptString,decryptString);
    
    NSString *des3Key = @"abcd1245kjln9870ijkn6758";
    encryptString = [DesEncrypt stringBy3DesCBCEncrypt:string key:des3Key iv:desIV];
    decryptString = [DesEncrypt stringBy3DesCBCDecrypt:encryptString key:des3Key iv:desIV];
    NSLog(@"3Des CBC：\n加密：%@\n解密：%@\n",encryptString,decryptString);

    encryptString = [DesEncrypt stringBy3DesECBEncrypt:string key:des3Key];
    decryptString = [DesEncrypt stringBy3DesECBDecrypt:encryptString key:des3Key];
    NSLog(@"3Des EBC：\n加密：%@\n解密：%@\n",encryptString,decryptString);
}
- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
