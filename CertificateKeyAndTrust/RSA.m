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
#include "Global.h"
#import "RSA.h"
#import <Security/Security.h>
#import "NSData+Base64.h"

@implementation RSA


static const UInt8 publicKeyIdentifier[] = "com.example.publickey\0";
static const UInt8 privateKeyIdentifier[] = "com.example.privatekey\0";
NSString *x509PublicHeader = @"-----BEGIN PUBLIC KEY-----";
NSString *x509PublicFooter = @"-----END PUBLIC KEY-----";
NSString *pKCS1PublicHeader = @"-----BEGIN RSA PUBLIC KEY-----";
NSString *pKCS1PublicFooter = @"-----END RSA PUBLIC KEY-----";
NSString *pemPrivateHeader = @"-----BEGIN RSA PRIVATE KEY-----";
NSString *pemPrivateFooter = @"-----END RSA PRIVATE KEY-----";
static unsigned char oidSequence[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };


# pragma mark -
# pragma mark Encryption/Decryption Methods:
-(NSString *)decryptWithPrivateKey:(NSString *)cipherString
{
 size_t plainBufferSize;;
 uint8_t *plainBuffer;
 
 SecKeyRef privateKey = NULL;
 
 NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *)privateKeyIdentifier)];
 
 NSMutableDictionary *queryPrivateKey = [[NSMutableDictionary alloc] init];
 [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
 [queryPrivateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
 [queryPrivateKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
 
 SecItemCopyMatching((CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKey);
 
 if (privateKey)
 {
  plainBufferSize = SecKeyGetBlockSize(privateKey);
  plainBuffer = malloc(plainBufferSize);
  
  NSData *incomingData = [NSData dataFromBase64String:cipherString];
  uint8_t *cipherBuffer = (uint8_t*)[incomingData bytes];
  size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
  
  // Ordinarily, you would split the data up into blocks
  // equal to plainBufferSize, with the last block being
  // shorter. For simplicity, this example assumes that
  // the data is short enough to fit.
  if (plainBufferSize < cipherBufferSize)
  {
   printf("Could not decrypt.  Packet too large.\n");
   
   if(privateKey) CFRelease(privateKey);
   if(queryPrivateKey) [queryPrivateKey release];
   
   return nil;
  }
  
  SecKeyDecrypt(privateKey, kSecPaddingPKCS1, cipherBuffer, cipherBufferSize, plainBuffer, &plainBufferSize); 
  
  NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
  NSString *decryptedString = [[[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding] autorelease];
  
  if(privateKey) CFRelease(privateKey);
  if(queryPrivateKey) [queryPrivateKey release];
  
  return decryptedString;
 }
 else
 {
  if(queryPrivateKey) [queryPrivateKey release];
  
  return nil;
 }
}



-(NSString *)encryptWithPublicKey:(NSString *)plainTextString
{
 SecKeyRef publicKey = NULL;
 NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *)publicKeyIdentifier)];
 NSMutableDictionary *queryPublicKey = [[NSMutableDictionary alloc] init];
 [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
 [queryPublicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
 [queryPublicKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
 
 SecItemCopyMatching((CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKey);
 
 if (publicKey)
 {
  size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
  uint8_t *cipherBuffer = malloc(cipherBufferSize);
  
  NSLog(@"\nCipher buffer size: %lu\n\n",cipherBufferSize);
  
  uint8_t *nonce = (uint8_t *)[plainTextString UTF8String];
  
  //  Error handling:
  // Ordinarily, you would split the data up into blocks
  // equal to cipherBufferSize, with the last block being
  // shorter. For simplicity, this example assumes that
  // the data is short enough to fit.
  if (cipherBufferSize < sizeof(nonce))
  {
   printf("Could not decrypt.  Packet too large.\n");
   
   if(publicKey) CFRelease(publicKey);
   if(queryPublicKey) [queryPublicKey release];
   free(cipherBuffer);
   
   return nil;
  }
  
  SecKeyEncrypt(publicKey, kSecPaddingPKCS1, nonce, strlen( (char*)nonce ) + 1, &cipherBuffer[0], &cipherBufferSize);
  
  NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
  
  if (VERBOSE)
   NSLog(@"\nBase 64 Encrypted String:\n%@\n\n",[encryptedData base64EncodedString]);
  
  if(publicKey) CFRelease(publicKey);
  if(queryPublicKey) [queryPublicKey release];
  free(cipherBuffer);
  
  return [encryptedData base64EncodedString];
 }
 else
 {
  if(queryPublicKey) [queryPublicKey release];
  return nil;
 }
}


# pragma mark -
# pragma mark Public Key Import/Export Methods:
size_t encodeLength(unsigned char * buf, size_t length)
{ 
 if (length < 128)
 {
  buf[0] = length;
  return 1;
 }
 
 size_t i = (length / 256) + 1;
 buf[0] = i + 0x80;
 for (size_t j = 0 ; j < i; ++j)
 {        
  buf[i - j] = length & 0xFF;  
  length = length >> 8;
 }
 
 return i + 1;
}



-(NSString *)getPEMFormattedPrivateKey
{ 
 NSData *privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *) privateKeyIdentifier)];
 
 NSMutableDictionary * queryPrivateKey = [[[NSMutableDictionary alloc] init] autorelease];
 [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
 [queryPrivateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
 [queryPrivateKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnData];
 
 NSData * privateKeyBits;
 OSStatus err = SecItemCopyMatching((CFDictionaryRef)queryPrivateKey,(CFTypeRef *)&privateKeyBits);
 
 if (err != noErr)
  return nil;
 
 NSMutableData * encKey = [[NSMutableData alloc] init];
 
 NSLog(@"\n%@\n\n",[[NSData dataWithBytes:privateKeyBits length:[privateKeyBits length]] description]);
 
 [encKey appendData:privateKeyBits];
 [privateKeyBits release];
 
 NSString *returnString = [NSString stringWithFormat:@"%@\n",pemPrivateHeader];
 returnString = [returnString stringByAppendingString:[encKey base64EncodedString]];
 returnString = [returnString stringByAppendingFormat:@"\n%@",pemPrivateFooter];
 
 NSLog(@"\nPEM formatted key:\n%@\n\n",returnString);
 
 [encKey release];
 return returnString;
}


-(NSString *)getX509FormattedPublicKey
{ 
 NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *) publicKeyIdentifier)];
 
 NSMutableDictionary * queryPublicKey = [[[NSMutableDictionary alloc] init] autorelease];
 [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
 [queryPublicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
 [queryPublicKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnData];
 
 NSData * publicKeyBits;
 OSStatus err = SecItemCopyMatching((CFDictionaryRef)queryPublicKey,(CFTypeRef *)&publicKeyBits);
 
 if (err != noErr)
 {
  return nil;
 }
 
 unsigned char builder[15];
 NSMutableData *encKey = [[NSMutableData alloc] init];
 int bitstringEncLength;
 
 if  ([publicKeyBits length ] + 1  < 128 )
  bitstringEncLength = 1 ;
 else
  bitstringEncLength = (([publicKeyBits length ] +1 ) / 256 ) + 2 ; 
 
 builder[0] = 0x30;
 size_t i = sizeof(oidSequence) + 2 + bitstringEncLength + [publicKeyBits length];
 size_t j = encodeLength(&builder[1], i);
 [encKey appendBytes:builder length:j +1];
 
 [encKey appendBytes:oidSequence length:sizeof(oidSequence)];
 
 builder[0] = 0x03;
 j = encodeLength(&builder[1], [publicKeyBits length] + 1);
 builder[j+1] = 0x00;
 [encKey appendBytes:builder length:j + 2];
 
 [encKey appendData:publicKeyBits];
 [publicKeyBits release];
 
 NSString *returnString = [NSString stringWithFormat:@"%@\n",x509PublicHeader];
 returnString = [returnString stringByAppendingString:[encKey base64EncodedString]];
 returnString = [returnString stringByAppendingFormat:@"\n%@",x509PublicFooter];
 
 NSLog(@"\nPEM formatted key:\n%@\n\n",returnString);
 
 [encKey release];
 return returnString;
}



- (BOOL)setPrivateKey:(NSString *)pemPrivateKeyString
{
 NSData *privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *)privateKeyIdentifier)];
 
 NSMutableDictionary *privateKey = [[[NSMutableDictionary alloc] init] autorelease];
 [privateKey setObject:(id) kSecClassKey forKey:(id)kSecClass];
 [privateKey setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [privateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
 SecItemDelete((CFDictionaryRef)privateKey);
 
 NSString *strippedKey = [NSString string];
 if (([pemPrivateKeyString rangeOfString:pemPrivateHeader].location != NSNotFound) && ([pemPrivateKeyString rangeOfString:pemPrivateFooter].location != NSNotFound))
 {
  strippedKey = [[pemPrivateKeyString stringByReplacingOccurrencesOfString:pemPrivateHeader withString:@""] stringByReplacingOccurrencesOfString:pemPrivateFooter withString:@""];
  strippedKey = [[strippedKey stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@" " withString:@""];
 }
 else
  return NO;
 
 NSData *strippedPrivateKeyData = [NSData dataFromBase64String:strippedKey];
 
 if (VERBOSE)
  NSLog(@"\nStripped Private Key Base 64:\n%@\n\n",strippedKey);
 
 CFTypeRef persistKey = nil;
 [privateKey setObject:strippedPrivateKeyData forKey:(id)kSecValueData];
 [privateKey setObject:(id) kSecAttrKeyClassPrivate forKey:(id)kSecAttrKeyClass];
 [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnPersistentRef];
 
 OSStatus secStatus = SecItemAdd((CFDictionaryRef)privateKey, &persistKey);
 
 if (persistKey != nil) CFRelease(persistKey);
 
 if ((secStatus != noErr) && (secStatus != errSecDuplicateItem))
  return NO;
 
 SecKeyRef keyRef = nil;
 [privateKey removeObjectForKey:(id)kSecValueData];
 [privateKey removeObjectForKey:(id)kSecReturnPersistentRef];
 [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
 [privateKey setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 
 SecItemCopyMatching((CFDictionaryRef)privateKey,(CFTypeRef *)&keyRef);
 
 if(keyRef) CFRelease(keyRef);
 
 if (keyRef == nil) return NO;

 return YES;
}



- (BOOL)setPublicKey:(NSString *)pemPublicKeyString
{
 NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *)publicKeyIdentifier)];
 
 NSMutableDictionary *publicKey = [[[NSMutableDictionary alloc] init] autorelease];
 [publicKey setObject:(id) kSecClassKey forKey:(id)kSecClass];
 [publicKey setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [publicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
 SecItemDelete((CFDictionaryRef)publicKey);
 
 BOOL isX509 = NO;
 
 NSString *strippedKey = [NSString string];
 if (([pemPublicKeyString rangeOfString:x509PublicHeader].location != NSNotFound) && ([pemPublicKeyString rangeOfString:x509PublicFooter].location != NSNotFound))
 {
  strippedKey = [[pemPublicKeyString stringByReplacingOccurrencesOfString:x509PublicHeader withString:@""] stringByReplacingOccurrencesOfString:x509PublicFooter withString:@""];
  strippedKey = [[strippedKey stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@" " withString:@""];
  
  isX509 = YES;
 }
 else if (([pemPublicKeyString rangeOfString:pKCS1PublicHeader].location != NSNotFound) && ([pemPublicKeyString rangeOfString:pKCS1PublicFooter].location != NSNotFound))
 {
  strippedKey = [[pemPublicKeyString stringByReplacingOccurrencesOfString:pKCS1PublicHeader withString:@""] stringByReplacingOccurrencesOfString:pKCS1PublicFooter withString:@""];
  strippedKey = [[strippedKey stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@" " withString:@""];
  
  isX509 = NO;
 }
 else
  return NO;
 
 NSData *strippedPublicKeyData = [NSData dataFromBase64String:strippedKey];
 NSLog(@"\nPublic Key Bytes:\n%@\n\n",[strippedPublicKeyData description]);

 if (isX509)
 {
  unsigned char * bytes = (unsigned char *)[strippedPublicKeyData bytes];
  size_t bytesLen = [strippedPublicKeyData length];
  
  size_t i = 0;
  if (bytes[i++] != 0x30)
   return NO;
  
  /* Skip size bytes */
  if (bytes[i] > 0x80)
   i += bytes[i] - 0x80 + 1;
  else
   i++;
  
  if (i >= bytesLen)
   return NO;
  
  if (bytes[i] != 0x30)
   return NO;
  
  /* Skip OID */
  i += 15;
  
  if (i >= bytesLen - 2)
   return NO;
  
  if (bytes[i++] != 0x03)
   return NO;
  
  /* Skip length and null */
  if (bytes[i] > 0x80)
   i += bytes[i] - 0x80 + 1;
  else
   i++;
  
  if (i >= bytesLen)
   return NO;
  
  if (bytes[i++] != 0x00)
   return NO;
  
  if (i >= bytesLen)
   return NO;
  
  strippedPublicKeyData = [NSData dataWithBytes:&bytes[i] length:bytesLen - i];
 }
 
 if (strippedPublicKeyData == nil)
  return NO;
 
 if (VERBOSE)
  NSLog(@"\nStripped Public Key Bytes:\n%@\n\n",[strippedPublicKeyData description]);
 
 CFTypeRef persistKey = nil;
 [publicKey setObject:strippedPublicKeyData forKey:(id)kSecValueData];
 [publicKey setObject:(id) kSecAttrKeyClassPublic forKey:(id)kSecAttrKeyClass];
 [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnPersistentRef];
 
 OSStatus secStatus = SecItemAdd((CFDictionaryRef)publicKey, &persistKey);
 
 if (persistKey != nil) CFRelease(persistKey);
 
 if ((secStatus != noErr) && (secStatus != errSecDuplicateItem))
  return NO;
 
 SecKeyRef keyRef = nil;
 [publicKey removeObjectForKey:(id)kSecValueData];
 [publicKey removeObjectForKey:(id)kSecReturnPersistentRef];
 [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
 [publicKey setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 
 SecItemCopyMatching((CFDictionaryRef)publicKey,(CFTypeRef *)&keyRef);
 
 if(keyRef) CFRelease(keyRef);
 
 if (keyRef == nil) return NO;
 
 return YES;
}


# pragma mark -
# pragma mark Key pair generation method:
-(void)generateKeyPair
{
 NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
 NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
 NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
 
 NSData *publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *)publicKeyIdentifier)];
 NSData *privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *)privateKeyIdentifier)];
 
 NSMutableDictionary *privateKeyDictionary = [[NSMutableDictionary alloc] init];
 [privateKeyDictionary setObject:(id) kSecClassKey forKey:(id)kSecClass];
 [privateKeyDictionary setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [privateKeyDictionary setObject:privateTag forKey:(id)kSecAttrApplicationTag];
 SecItemDelete((CFDictionaryRef)privateKeyDictionary);
 
 NSMutableDictionary *publicKeyDictionary = [[NSMutableDictionary alloc] init];
 [publicKeyDictionary setObject:(id) kSecClassKey forKey:(id)kSecClass];
 [publicKeyDictionary setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [publicKeyDictionary setObject:publicTag forKey:(id)kSecAttrApplicationTag];
 SecItemDelete((CFDictionaryRef)publicKeyDictionary);
 
 [privateKeyDictionary release];
 [publicKeyDictionary release];
 
 SecKeyRef publicKey = NULL;
 SecKeyRef privateKey = NULL;
 
 [keyPairAttr setObject:(id)kSecAttrKeyTypeRSA
                 forKey:(id)kSecAttrKeyType];
 [keyPairAttr setObject:[NSNumber numberWithInt:1024]
                 forKey:(id)kSecAttrKeySizeInBits];
 
 
 [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecAttrIsPermanent];
 [privateKeyAttr setObject:privateTag forKey:(id)kSecAttrApplicationTag];
 
 [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecAttrIsPermanent];
 [publicKeyAttr setObject:publicTag forKey:(id)kSecAttrApplicationTag];
 
 [keyPairAttr setObject:privateKeyAttr forKey:(id)kSecPrivateKeyAttrs];
 [keyPairAttr setObject:publicKeyAttr forKey:(id)kSecPublicKeyAttrs];
 
 SecKeyGeneratePair((CFDictionaryRef)keyPairAttr,&publicKey, &privateKey);
 
 if(privateKeyAttr) [privateKeyAttr release];
 if(publicKeyAttr) [publicKeyAttr release];
 if(keyPairAttr) [keyPairAttr release];
 if(publicKey) CFRelease(publicKey);
 if(privateKey) CFRelease(privateKey);
}

@end