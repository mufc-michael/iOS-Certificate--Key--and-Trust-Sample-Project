//
//  NSString+JSON.h
//  iOSKuapay
//
//  Created by Patrick Hogan on 11/29/11.
//  Copyright (c) 2011 Kuapay LLC. All rights reserved.
//

typedef enum
{
 BOOLEAN,
 INT,
 FLOAT,
 LONGLONG,
 STRING,
 ARRAY,
 DICTIONARY,
 STRINGORDICTIONARY,
 STRINGORARRAY,
 STRINGORNUMBER
} ExpectedType;

@interface NSDictionary (ParseJSON)

-(id)extractObjectOrThrow:(NSString *)name type:(ExpectedType)type function:(const char *)function line:(NSInteger)line;
-(id)extractObjectOrReturnNil:(NSString *)name type:(ExpectedType)type;

@end