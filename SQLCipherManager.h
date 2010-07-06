//
//  SQLCipherManager.h
//  Strip
//
//  Created by Billy Gray on 12/30/09.
//  Copyright 2009 Zetetic LLC. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "sqlite3.h"

#define ERR_SQLCIPHER_COMMAND_FAILED 1

@class SQLCipherManager;

@protocol SQLCipherManagerDelegate <NSObject>
@optional
- (void)didOpenDatabase;
- (void)didCreateDatabase;
- (void)didEncounterRekeyError;
- (void)didEncounterDatabaseError:(NSString *)error;
- (void)sqlCipherManagerWillRekeyDatabase;
- (void)sqlCipherManagerDidRekeyDatabase;
@end

@interface SQLCipherManager : NSObject {
	sqlite3 *database;
	BOOL inTransaction;
	id delegate;
	NSString *cachedPassword;
	NSString *databasePath;
}

@property (nonatomic) sqlite3 *database;
@property (nonatomic) BOOL inTransaction;
@property (nonatomic, assign) id<SQLCipherManagerDelegate> delegate;

@property (nonatomic, retain) NSString *cachedPassword;
@property (nonatomic, retain) NSString *databasePath;

+ (id)sharedManager;
+ (BOOL)passwordIsValid:(NSString *)password;

- (NSNumber *)databaseSize;

// Open, Close, and Re-Key methods
- (void)createDatabaseWithPassword:(NSString *)password;
- (BOOL)openDatabaseWithPassword:(NSString *)password;
- (BOOL)openDatabaseWithCachedPassword;
- (BOOL)openDatabaseWithOptions:(NSString*)password cipher:(NSString*)cipher iterations:(NSString *)iterations;
- (BOOL)rekeyDatabaseWithPassword:(NSString *)password;
- (BOOL)rekeyDatabaseWithOptions:(NSString*)password cipher:(NSString*)cipher iterations:(NSString *)iterations;
- (void)closeDatabase;
- (void)reallyCloseDatabase;
- (BOOL)isDatabaseUnlocked;

// Backup and File Location methods
- (NSString *)databaseDirectory;
- (BOOL)databaseExists;
- (NSString *)pathToDatabase;
- (NSString *)pathToRollbackDatabase;
- (BOOL)restoreDatabaseFromRollback:(NSError **)error;
- (BOOL)restoreDatabaseFromFileAtPath:(NSString *)path error:(NSError **)error;

// Schema methods
- (NSUInteger)getSchemaVersion;
- (void)setSchemaVersion:(NSInteger)version;

// Query / Transaction methods
- (void)execute:(NSString *)sqlCommand;
- (BOOL)execute:(NSString *)sqlCommand error:(NSError **)error;
- (void)beginTransaction;
- (void)commitTransaction;
- (void)rollbackTransaction;
- (NSString *)getScalarWith:(NSString *)query;

@end

