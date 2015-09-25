//
//  NSURL+NYPLURLAdditions.m
//  Simplified
//
//  Created by Sam Tarakajian on 9/24/15.
//  Copyright © 2015 NYPL Labs. All rights reserved.
//

#import "NSURL+NYPLURLAdditions.h"

@implementation NSURL (NYPLURLAdditions)

- (BOOL) isNYPLExternal
{
  if (self.isFileURL)
    return NO;
  
  if ([self.scheme isEqualToString:@"about"])
    return NO;
  
  if ([self.host isEqualToString:@"127.0.0.1"] || [self.host isEqualToString:@"::1"] || [self.host isEqualToString:@"localhost"])
    return NO;
  
  return YES;
}

@end
