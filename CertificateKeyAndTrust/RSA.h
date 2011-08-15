//
//  CertificateKeyAndTrustAppDelegate.h
//  CertificateKeyAndTrust
//
//  Created by Patrick Hogan on 6/24/11.
//  Copyright 2011 Kuapay LLC. All rights reserved.
//
//  Information borrowed from,
//
//  http://developer.apple.com/library/mac/#documentation/Security/Conceptual/CertKeyTrustProgGuide/iPhone_Tasks/iPhone_Tasks.html ,
//
//  and special thanks to Berin for the following critical resources.  Most of the code here was taken from his blog.
//
//  http://blog.wingsofhermes.org/?p=42 , http://blog.wingsofhermes.org/?p=75
//
#import <Foundation/Foundation.h>

@interface RSA : NSObject { }

-(void)generateKeyPair;

// These methods are here to import RSA keys from strings and place in your keychain
// If boolean is set to "YES" then the key is assumed to be x509 formatted, otherwise it is taken to be PKCS1 formatted.
-(BOOL)setPublicKey:(NSString *)pemPublicKeyString;
-(BOOL)setPrivateKey:(NSString *)pemPrivateKeyString;

// These methods are here to export RSA keys from keychain to strings
// If boolean is set to "YES" then the key is assumed to be x509 formatted, otherwise it is taken to be PKCS1 formatted.
-(NSString *)getX509FormattedPublicKey;
-(NSString *)getPEMFormattedPrivateKey;

-(NSString *)encryptWithPublicKey:(NSString *)plainTextString;
-(NSString *)decryptWithPrivateKey:(NSString *)cipherString;

size_t encodeLength(unsigned char * buf, size_t length);

@end