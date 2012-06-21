//
//  SQLCipherManagerTestsOSX.h
//  SQLCipherManagerTestsOSX
//
//  Created by Billy Gray on 6/21/12.
//  Copyright (c) 2012 Zetetic LLC. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>
#import "SQLCipherManager.h"

@interface SQLCipherManagerTestsOSX : SenTestCase <SQLCipherManagerDelegate>
@property (nonatomic, retain) SQLCipherManager *sqlCipherManager;
@end
