//
//  ViewController.m
//  AesEncrypt
//
//  Created by ElaineYin on 2018/3/29.
//  Copyright © 2018年 EL. All rights reserved.
//

#import "ViewController.h"
#import "AesEncrypt.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    [self AesTest];
}

- (void)AesTest {
    NSString * string = @"";
    for (NSInteger i = 0; i < 10; i ++ ) {
        string = [string stringByAppendingString:@"Hello, my name is ElaineYin, you can call me MuMu too!"];
    }
    
    NSString *aes256Key = @"Hello1I2am3Elai4Hello1I2am3Elai4";
    
    NSString *encryptString = [AesEncrypt stringByAes256Encrypt:string key:aes256Key];
    NSString *decryptString = [AesEncrypt stringByAes256Decrypt:encryptString key:aes256Key];
    NSLog(@"Aes256ECB：\n加密：%@\n解密：%@\n",encryptString,decryptString);
    NSString *aes128Key = @"ello1I2am3Elai4H";
    encryptString = [AesEncrypt stringByAes128CBCEncrypt:string key:aes128Key];
    decryptString = [AesEncrypt stringByAes128CBCDecrypt:encryptString key:aes128Key];
    NSLog(@"Aes128CBC：\n加密：%@\n解密：%@\n",encryptString,decryptString);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
