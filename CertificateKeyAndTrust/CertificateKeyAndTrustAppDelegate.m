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
#import "CertificateKeyAndTrustAppDelegate.h"
#import "RSA.h"
#import "Global.h"

@implementation CertificateKeyAndTrustAppDelegate
@synthesize window;


-(void)sampleEncryption:(RSA *)rsa
{
 // Borrowed code from Apple's Certificate, Key, and Trust Programming guide:
 [rsa generateKeyPair];
 
 // Encrypt and decrypt sample string:
 NSString *base64EncodedString = [rsa encryptWithPublicKey:@"This is a test.  Can you encrypt and decrypt this?"];
 NSLog(@"\nDecrypted String:\n%@\n\n",[rsa decryptWithPrivateKey:base64EncodedString]);
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
 RSA *rsa = [[RSA alloc] init];
 
 // First Generate a Key pair in house and output the formatted keys:
 [self sampleEncryption:rsa];
 [rsa getX509FormattedPublicKey];
 [rsa getPEMFormattedPrivateKey];
 
 // Import Public Key string from bundle:
 NSError *error = nil;
 NSString *publicKeyString = [NSString stringWithContentsOfFile:[[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"x509PublicKey.pem"] encoding:NSUTF8StringEncoding error:&error];
 
 if (VERBOSE)
  NSLog(@"\nPublic Key String:\n%@\n\n",publicKeyString);
 
 // Add public key to keychain:
 [rsa setPublicKey:publicKeyString];

 // Encrypt sample string:
 NSString *encryptedString = [rsa encryptWithPublicKey:@"This is a test.  Can you encrypt and decrypt this?"];

 // Import Private Key string from bundle:
 NSString *privateKeyString = [NSString stringWithContentsOfFile:[[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"pkcs1PrivateKey.pem"] encoding:NSUTF8StringEncoding error:&error];
 
 if (VERBOSE)
  NSLog(@"\nPrivate String:\n%@\n\n",privateKeyString);
 
 // Add private key to the keychain:
 [rsa setPrivateKey:privateKeyString];
 
 // Decrypt sample cipher text:
 NSLog(@"\nDecrypted string:\n%@\n\n",[rsa decryptWithPrivateKey:encryptedString]);
 
 [rsa release];
  
 return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {}

- (void)applicationDidEnterBackground:(UIApplication *)application {}

- (void)applicationWillEnterForeground:(UIApplication *)application {}

- (void)applicationDidBecomeActive:(UIApplication *)application {}

- (void)applicationWillTerminate:(UIApplication *)application {}

- (void)dealloc
{
 [super dealloc];

 [window release];
}

@end
