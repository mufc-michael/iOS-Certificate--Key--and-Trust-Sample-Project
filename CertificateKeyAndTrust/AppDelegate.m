//
//  AppDelegate.m
//  iOSCryptoExample
//
//  Created by Patrick Hogan on 1/15/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "AppDelegate.h"
#import "ViewController.h"

@implementation AppDelegate
@synthesize window = _window;


-(BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{ 
 self.window = [[[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]] autorelease];
 self.window.backgroundColor = [UIColor whiteColor];
 
 // Look to the viewController viewDidLoad method for examples :)
 
 ViewController *viewController = [[ViewController alloc] init];
 self.window.rootViewController = viewController;
 
 [self.window makeKeyAndVisible];
 
 return YES;
}


-(void)applicationWillResignActive:(UIApplication *)application
{
}


-(void)applicationDidEnterBackground:(UIApplication *)application
{
}


-(void)applicationWillEnterForeground:(UIApplication *)application
{
}


-(void)applicationDidBecomeActive:(UIApplication *)application
{
}


-(void)applicationWillTerminate:(UIApplication *)application
{
}


-(void)dealloc
{
 [_window release];
 [super dealloc];
}

@end
