//
//  NSString+JSON.m
//  iOSKuapay
//
//  Created by Patrick Hogan on 11/29/11.
//  Copyright (c) 2011 Kuapay LLC. All rights reserved.
//

#import "Exception.h"
#import "NSDictionary+ParseJSON.h"


@interface NSDictionary ()

+(NSArray *)types:(ExpectedType)type;

-(id)valueForKeyPath:(NSString *)keyPath type:(ExpectedType)type;

@end


@implementation NSDictionary (ParseJSON)


-(id)extractObjectOrThrow:(NSString *)name type:(ExpectedType)type function:(const char *)function line:(NSInteger)line
{
 if ([self valueForKeyPath:name] || [self valueForKey:name] != (id)[NSNull null])
 {
  NSArray *types = [NSDictionary types:type];
  
  for (id element in types)
  {
   if ([[[self valueForKeyPath:name] class] isSubclassOfClass:element]) return [self valueForKeyPath:name type:type];
  }
 }
  
 [Exception raise:FAILURE function:function line:line description:[NSString stringWithFormat:@"Unexpected type exception: %@ not expected type.", name]];
 
 return nil;
}


-(id)extractObjectOrReturnNil:(NSString *)name type:(ExpectedType)type
{
 if ([self valueForKey:name] || [self valueForKey:name] != (id)[NSNull null])
 {
  NSArray *types = [NSDictionary types:type];

  for (id element in types)
  {
   if ([[[self valueForKeyPath:name] class] isSubclassOfClass:element]) return [self valueForKeyPath:name type:type];
  }
 }
  
 return nil;
}


+(NSArray *)types:(ExpectedType)type
{
 switch (type)
 {
  case BOOLEAN:
   return [NSArray arrayWithObject:[NSNumber class]];
   break;
  case INT:
   return [NSArray arrayWithObjects:[NSString class], [NSNumber class], nil];
   break;
  case FLOAT:
   return [NSArray arrayWithObjects:[NSString class], [NSNumber class], nil];
   break;
  case LONGLONG:
   return [NSArray arrayWithObjects:[NSString class], [NSNumber class], nil];
   break;
  case STRING:
   return [NSArray arrayWithObject:[NSString class]];
   break;
  case ARRAY:
   return [NSArray arrayWithObject:[NSArray class]];
   break;
  case DICTIONARY:
   return [NSArray arrayWithObject:[NSDictionary class]];
   break;
  case STRINGORDICTIONARY:
   return [NSArray arrayWithObjects:[NSString class], [NSDictionary class], nil];
   break;
  case STRINGORARRAY:
   return [NSArray arrayWithObjects:[NSString class], [NSArray class], nil];
   break;
  case STRINGORNUMBER:
   return [NSArray arrayWithObjects:[NSString class], [NSNumber class], nil];
   break;
  default:
   return nil;
   break;
 } 
}


-(id)valueForKeyPath:(NSString *)keyPath type:(ExpectedType)type
{
 id value = [self valueForKeyPath:keyPath];
 switch (type)
 {
  case BOOLEAN:
   if ([value boolValue] == 0) return [NSNumber numberWithBool:NO];
   else return [NSNumber numberWithBool:YES];
   break;
  case INT:
   return [NSNumber numberWithInt:[value intValue]];
   break;
  case FLOAT:
   return [NSNumber numberWithFloat:[value floatValue]];
   break;
  case LONGLONG:
   return [NSNumber numberWithLongLong:[value longLongValue]];
   break;
  case STRING:
   return value;
   break;
  case ARRAY:
   return value;
   break;
  case DICTIONARY:
   return value;
   break;
  case STRINGORDICTIONARY:
   return value;
   break;
  case STRINGORARRAY:
   return value;
   break;
  case STRINGORNUMBER:
   return value;
   break;
  default:
   return nil;
   break;
 }
}



@end
