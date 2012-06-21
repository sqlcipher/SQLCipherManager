//
//  SQLCipherManagerTestsOSX.m
//  SQLCipherManagerTestsOSX
//
//  Created by Billy Gray on 6/21/12.
//  Copyright (c) 2012 Zetetic LLC. All rights reserved.
//

#import "SQLCipherManagerTestsOSX.h"

@implementation SQLCipherManagerTestsOSX
@synthesize sqlCipherManager=_sqlCipherManager;

- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *dbFileURL = [NSURL fileURLWithPath:[[fm currentDirectoryPath] stringByAppendingPathComponent:@"test.db"]];
    self.sqlCipherManager = [SQLCipherManager sharedManager];
    self.sqlCipherManager.delegate = self;
    if ([fm fileExistsAtPath:[dbFileURL path]]) {
        [self.sqlCipherManager openDatabaseWithPassword:@"xyz"];
    }
    else {
        [self.sqlCipherManager createDatabaseWithPassword:@"xyz"];
    }
    // let's ensure the db manager is open and working already
    BOOL isDatabaseUnlocked = [self.sqlCipherManager isDatabaseUnlocked];
    STAssertTrue(isDatabaseUnlocked, @"Could not open database, it appears locked");
}

- (void)tearDown
{
    // Tear-down code here.
    [self.sqlCipherManager closeDatabase];
    self.sqlCipherManager = nil;
    
    [super tearDown];
}

- (void)testExample
{
    // let's ensure the db manager is open and working already
    BOOL isDatabaseUnlocked = [self.sqlCipherManager isDatabaseUnlocked];
    STAssertTrue(isDatabaseUnlocked, @"Could not open database, it appears locked");
}

@end
