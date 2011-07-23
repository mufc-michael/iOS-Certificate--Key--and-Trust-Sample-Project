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
NSString *pKCS1PublicHeader = @"-----BEGIN PUBLIC KEY-----";
NSString *pKCS1PublicFooter = @"-----END PUBLIC KEY-----";
NSString *pKCS1PrivateHeader = @"-----BEGIN RSA PRIVATE KEY-----";
NSString *pKCS1PrivateFooter = @"-----END RSA PRIVATE KEY-----";
static unsigned char oidSequence[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };


# pragma mark -
# pragma mark Encryption/Decryption Methods:
-(NSString *)decryptWithPrivateKey:(NSString *)inputString
{
 OSStatus status = noErr;
 
 size_t plainBufferSize;;
 uint8_t *plainBuffer;
 
 SecKeyRef privateKey = NULL;
 
 NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *)privateKeyIdentifier)];
 
 NSMutableDictionary *queryPrivateKey = [[NSMutableDictionary alloc] init];
 [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
 [queryPrivateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
 [queryPrivateKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
 
 status = SecItemCopyMatching((CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKey);
 
 if (status) 
 {
  if(privateKey) CFRelease(privateKey);
  if(queryPrivateKey) [queryPrivateKey release];
  
  return nil;
 }
 
 //  Allocate the buffer
 plainBufferSize = SecKeyGetBlockSize(privateKey);
 plainBuffer = malloc(plainBufferSize);
 
 NSData *incomingData = [NSData dataFromBase64String:inputString];
 uint8_t *cipherBuffer = (uint8_t*)[incomingData bytes];
 
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
 
 status = SecKeyDecrypt(privateKey, kSecPaddingPKCS1, cipherBuffer, cipherBufferSize, plainBuffer, &plainBufferSize);
 
 if (status) 
 {
  if(privateKey) CFRelease(privateKey);
  if(queryPrivateKey) [queryPrivateKey release];
  
  return nil;
 }

 NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
 NSString *decryptedString = [[[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding] autorelease];
 
 if(privateKey) CFRelease(privateKey);
 if(queryPrivateKey) [queryPrivateKey release];
 
 return decryptedString;
}



-(NSString *)encryptWithPublicKey:(NSString *)plainTextString
{
 OSStatus status = noErr;

 SecKeyRef publicKey = NULL;
 NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *)publicKeyIdentifier)];
 NSMutableDictionary *queryPublicKey = [[NSMutableDictionary alloc] init];
 [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
 [queryPublicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
 [queryPublicKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
 
 status = SecItemCopyMatching((CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKey);
 
 if (status) 
 {
  if(publicKey) CFRelease(publicKey);
  if(queryPublicKey) [queryPublicKey release];
  
  return nil;
 }
 
 //  Allocate a buffer
 cipherBufferSize = SecKeyGetBlockSize(publicKey);
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
  
  return nil;
 }
 
 status = SecKeyEncrypt(publicKey, kSecPaddingPKCS1, nonce, strlen( (char*)nonce ) + 1, &cipherBuffer[0], &cipherBufferSize);
 
 if (status) 
 {
  if(publicKey) CFRelease(publicKey);
  if(queryPublicKey) [queryPublicKey release];
  
  return nil;
 }
 
 NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];

 if (VERBOSE)
  NSLog(@"\nBase 64 Encrypted String:\n%@\n\n",[encryptedData base64EncodedString]);
 
 if(publicKey) CFRelease(publicKey);
 if(queryPublicKey) [queryPublicKey release];
 free(cipherBuffer);
 
 return [encryptedData base64EncodedString];
}


# pragma mark -
# pragma mark Public Key Import/Export Methods:
size_t encodeLength(unsigned char * buf, size_t length)
{ 
 // encode length in ASN.1 DER format
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



-(NSString *)getPKCS1FormattedPrivateKey
{ 
 NSData *privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *) privateKeyIdentifier)];
 
 // Now lets extract the private key - build query to get bits
 NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
 
 [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
 [queryPrivateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
 [queryPrivateKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnData];
 
 NSData * privateKeyBits;
 OSStatus err = SecItemCopyMatching((CFDictionaryRef)queryPrivateKey,(CFTypeRef *)&privateKeyBits);
 
 if (err != noErr)
 {
  [queryPrivateKey release];
  return nil;
 }
 
 // OK - that gives us the "BITSTRING component of a full DER
 // encoded RSA private key - we now need to build the rest
 
 NSMutableData * encKey = [[NSMutableData alloc] init];
 NSLog(@"\n%@\n\n",[[NSData dataWithBytes:privateKeyBits length:[privateKeyBits length]] description]);
 
 // Now the actual key
 [encKey appendData:privateKeyBits];
 [privateKeyBits release];
 
 // Now translate the result to a Base64 string
 NSString *ret = [NSString stringWithFormat:@"%@\n",pKCS1PrivateHeader];
 ret = [ret stringByAppendingString:[encKey base64EncodedString]];
 ret = [ret stringByAppendingFormat:@"\n%@",pKCS1PrivateFooter];
 
 NSLog(@"\nPEM formatted key:\n%@\n\n",ret);
 
 [queryPrivateKey release];
 [encKey release];
 return ret;
}


-(NSString *)getPublicKeyX509Formatted:(BOOL)formatBool
{ 
 NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *) publicKeyIdentifier)];
 
 // Now lets extract the public key - build query to get bits
 NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
 
 [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
 [queryPublicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
 [queryPublicKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnData];
 
 NSData * publicKeyBits;
 OSStatus err = SecItemCopyMatching((CFDictionaryRef)queryPublicKey,(CFTypeRef *)&publicKeyBits);
 
 if (err != noErr)
 {
  [queryPublicKey release];
  return nil;
 }
 
 // OK - that gives us the "BITSTRING component of a full DER
 // encoded RSA public key - we now need to build the rest
 
 unsigned char builder[15];
 NSMutableData * encKey = [[NSMutableData alloc] init];
 int bitstringEncLength;
 
 // When we get to the bitstring - how will we encode it?
 if  ([publicKeyBits length ] + 1  < 128 )
  bitstringEncLength = 1 ;
 else
  bitstringEncLength = (([publicKeyBits length ] +1 ) / 256 ) + 2 ; 
 
 // Overall we have a sequence of a certain length
 builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
 // Build up overall size made up of -
 // size of OID + size of bitstring encoding + size of actual key
 size_t i = sizeof(oidSequence) + 2 + bitstringEncLength + [publicKeyBits length];
 size_t j = encodeLength(&builder[1], i);
 
 if (formatBool)
 {
  [encKey appendBytes:builder length:j +1];
  
  // First part of the sequence is the OID
  [encKey appendBytes:oidSequence length:sizeof(oidSequence)];
  
  // Now add the bitstring
  builder[0] = 0x03;
  j = encodeLength(&builder[1], [publicKeyBits length] + 1);
  builder[j+1] = 0x00;
  [encKey appendBytes:builder length:j + 2];
 }
 
 // Now the actual key
 [encKey appendData:publicKeyBits];
 [publicKeyBits release];
 
 // Now translate the result to a Base64 string
 NSString *ret;
 if (formatBool)
 {
  ret = [NSString stringWithFormat:@"%@\n",x509PublicHeader];
  ret = [ret stringByAppendingString:[encKey base64EncodedString]];
  ret = [ret stringByAppendingFormat:@"\n%@",x509PublicFooter];
  
  NSLog(@"\nX.509 formatted key:\n%@\n\n",ret);
 }
 else
 {
  ret = [NSString stringWithFormat:@"%@\n",pKCS1PublicHeader];
  ret = [ret stringByAppendingString:[encKey base64EncodedString]];
  ret = [ret stringByAppendingFormat:@"\n%@",pKCS1PublicFooter];
  
  NSLog(@"\nPKCS1 formatted key:\n%@\n\n",ret);
 }
 [queryPublicKey release];
 [encKey release];
 return ret;
}



-(BOOL)setPKCS1PrivateKey:(NSString *)pKCS1PrivateKeyString
{
 NSString *strippedKey = [NSString string];
 NSArray  *stringArrayOfKeyComponents = [pKCS1PrivateKeyString componentsSeparatedByString:@"\n"];
 
 BOOL notFinished = NO;
 
 for (NSString *line in stringArrayOfKeyComponents)
 {
  if ([line isEqual:pKCS1PrivateHeader])
   notFinished = YES;
  else if ([line isEqual:pKCS1PrivateFooter])
   notFinished = NO;
  else if (notFinished)
   strippedKey = [strippedKey stringByAppendingString:line];
 }
 if (strippedKey.length == 0)
  return NO;
 
 // This will be base64 encoded, decode it.
 NSData *strippedPrivateKeyData = [NSData dataFromBase64String:strippedKey];
 
 if (VERBOSE)
  NSLog(@"\nStripped Private Key Base 64:\n%@\n\n",strippedKey);
 
 NSData *privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *)privateKeyIdentifier)];
 
 // Delete any old lingering key with the same tag
 NSMutableDictionary *privateKey = [[NSMutableDictionary alloc] init];
 [privateKey setObject:(id) kSecClassKey forKey:(id)kSecClass];
 [privateKey setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [privateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
 SecItemDelete((CFDictionaryRef)privateKey);
 
 CFTypeRef persistKey = nil;
 
 // Add persistent version of the key to system keychain
 [privateKey setObject:strippedPrivateKeyData forKey:(id)kSecValueData];
 [privateKey setObject:(id) kSecAttrKeyClassPrivate forKey:(id)kSecAttrKeyClass];
 [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnPersistentRef];
 
 OSStatus secStatus = SecItemAdd((CFDictionaryRef)privateKey, &persistKey);
 
 if (VERBOSE)
  NSLog(@"\nPrivate key keychain addition status: %lu",secStatus);
 
 if (persistKey != nil) CFRelease(persistKey);
 
 if ((secStatus != noErr) && (secStatus != errSecDuplicateItem))
 {
  [privateKey release];
  return NO;
 }
 
 // Now fetch the SecKeyRef version of the key
 SecKeyRef keyRef = nil;
 
 [privateKey removeObjectForKey:(id)kSecValueData];
 [privateKey removeObjectForKey:(id)kSecReturnPersistentRef];
 [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
 [privateKey setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 
 secStatus = SecItemCopyMatching((CFDictionaryRef)privateKey,(CFTypeRef *)&keyRef);
 
 [privateKey release];
 if(keyRef) CFRelease(keyRef);
 
 if (keyRef == nil || secStatus) return NO;
 
 return YES;
}



- (BOOL)setPublicKey:(NSString *)pemPublicKeyString isX509Formatted:(BOOL)formatBool
{
 NSString *strippedKey = [NSString string];
 NSArray  *stringArrayOfKeyComponents = [pemPublicKeyString componentsSeparatedByString:@"\n"];
 
 BOOL notFinished = NO;
 
 for (NSString *line in stringArrayOfKeyComponents)
 {
  if ([line isEqual:x509PublicHeader])
   notFinished = YES;
  else if ([line isEqual:x509PublicFooter])
   notFinished = NO;
  else if (notFinished)
   strippedKey = [strippedKey stringByAppendingString:line];
 }
 if (strippedKey.length == 0)
  return NO;
 
 // This will be base64 encoded, decode it.
 NSData *strippedPublicKeyData = [NSData dataFromBase64String:strippedKey];
 
 if (VERBOSE)
 {
  NSLog(@"\nPublic Key Base 64:\n%@\n\n",strippedKey);
  NSLog(@"\nPublic Key Hexadecimal:\n%@\n\n",[strippedPublicKeyData description]);
 }
 if (formatBool)
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
 
 if (VERBOSE)
 {
  NSLog(@"\nStripped Public Key Base 64:\n%@\n\n",strippedKey);
  NSLog(@"\nStripped Public Key Hexadecimal:\n%@\n\n",[strippedPublicKeyData description]);
 }
 
 NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *)publicKeyIdentifier)];

 // Delete any old lingering key with the same tag
 NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
 [publicKey setObject:(id) kSecClassKey forKey:(id)kSecClass];
 [publicKey setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 [publicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
 SecItemDelete((CFDictionaryRef)publicKey);
 
 CFTypeRef persistKey = nil;
 
 // Add persistent version of the key to system keychain
 [publicKey setObject:strippedPublicKeyData forKey:(id)kSecValueData];
 [publicKey setObject:(id) kSecAttrKeyClassPublic forKey:(id)kSecAttrKeyClass];
 [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnPersistentRef];
 
 OSStatus secStatus = SecItemAdd((CFDictionaryRef)publicKey, &persistKey);

 if (VERBOSE)
  NSLog(@"\nPublic key keychain addition status: %lu",secStatus);
 
 if (persistKey != nil) CFRelease(persistKey);
 
 if ((secStatus != noErr) && (secStatus != errSecDuplicateItem))
 {
  [publicKey release];
  return NO;
 }
 
 // Now fetch the SecKeyRef version of the key
 SecKeyRef keyRef = nil;
 
 [publicKey removeObjectForKey:(id)kSecValueData];
 [publicKey removeObjectForKey:(id)kSecReturnPersistentRef];
 [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
 [publicKey setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
 
 secStatus = SecItemCopyMatching((CFDictionaryRef)publicKey,(CFTypeRef *)&keyRef);
 
 [publicKey release];
 if(keyRef) CFRelease(keyRef);
 
 if (keyRef == nil || secStatus) return NO;
  
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
 
 // Delete any old lingering key with the same tag
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
