//
//  SQLCipherManager.h
//  Strip
//
//  Created by Billy Gray on 12/30/09.
//  Copyright 2009 Zetetic LLC. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <sqlite3.h>

#define ERR_SQLCIPHER_COMMAND_FAILED 1

extern NSString * _Nonnull const SQLCipherManagerCommandException;
extern NSString * _Nonnull const SQLCipherManagerUserInfoQueryKey;

@class SQLCipherManager;

@protocol SQLCipherManagerDelegate <NSObject>
@optional
- (void)didOpenDatabase:(SQLCipherManager *_Nonnull)manager;
- (void)didCreateDatabase:(SQLCipherManager *_Nonnull)manager;
- (void)didEncounterRekeyError;
- (void)didEncounterDatabaseError:(NSString *_Nullable)error;
- (void)sqlCipherManagerWillRekeyDatabase;
- (void)sqlCipherManagerDidRekeyDatabase;
@end

@interface SQLCipherManager : NSObject

@property (nonatomic, nullable) sqlite3 *database;
@property (nonatomic) BOOL inTransaction;
@property (nonatomic, weak, nullable) id<SQLCipherManagerDelegate> delegate;

@property (nonatomic, strong, nullable) NSString *cachedPassword;
@property (nonatomic, strong, nullable) NSString *databasePath;
@property (nonatomic, strong, nullable) NSURL *databaseUrl;
@property (nonatomic) BOOL useHMACPageProtection;
@property (nonatomic) NSInteger schemaVersion;
@property (nonatomic, readonly) BOOL isDatabaseUnlocked;
@property (nonatomic) NSInteger kdfIterations;
@property (nonatomic, readonly, nullable) dispatch_queue_t serialQueue;
@property (weak, nonatomic, readonly, nullable) NSString *cipherVersion;
@property (weak, nonatomic, readonly, nullable) NSString *cipherProvider;

- (id _Nonnull)initWithURL:(NSURL *_Nonnull)absoluteUrl;
- (id _Nonnull)initWithPath:(NSString *_Nonnull)path; // DEPRECATED
+ (id _Nonnull)sharedManager;
+ (void)setSharedManager:(SQLCipherManager *_Nonnull)manager;
+ (void)clearSharedManager;

+ (BOOL)passwordIsValid:(NSString *_Nonnull)password;

- (NSNumber *_Nullable)databaseSize;

// Open, Close, and Re-Key methods
- (void)createDatabaseWithPassword:(NSString *_Nonnull)password;
- (BOOL)openDatabaseWithPassword:(NSString *_Nonnull)password;
- (BOOL)openDatabaseWithCachedPassword;
- (BOOL)openDatabaseWithOptions:(NSString *_Nonnull)password cipher:(NSString *_Nonnull)cipher iterations:(NSInteger)iterations;
- (BOOL)openDatabaseWithOptions:(NSString *_Nonnull)password cipher:(NSString *_Nonnull)cipher iterations:(NSInteger)iterations withHMAC:(BOOL)useHMAC;
- (BOOL)openDatabaseWithOptions:(NSString *_Nonnull)password cipher:(NSString *_Nonnull)cipher iterations:(NSInteger)iterations withHMAC:(BOOL)useHMAC license:(NSString *_Nullable)licenseKey;
- (BOOL)openAndRekeyCFBDatabaseWithPassword:(NSString *_Nonnull)password __attribute__((deprecated));
- (BOOL)rekeyDatabaseWithPassword:(NSString *_Nonnull)password;
- (BOOL)rekeyDatabaseWithOptions:(NSString *_Nonnull)password
                          cipher:(NSString *_Nullable)cipher
                      iterations:(NSInteger)iterations
                           error:(NSError *_Nullable*_Nullable)error;
- (void)closeDatabase;
- (void)reallyCloseDatabase;
- (BOOL)reopenDatabase:(NSError *_Nullable*_Nullable)error;


// Open, Close, and Re-Key using Raw Data
- (void)createDatabaseWithRawData:(NSString *_Nonnull)rawHexKey;
- (BOOL)openDatabaseWithRawData:(NSString *_Nonnull)rawHexKey;
- (BOOL)openDatabaseWithRawData:(NSString *_Nonnull)rawHexKey cipher:(NSString *_Nonnull)cipher withHMAC:(BOOL)useHMAC;
- (BOOL)rekeyDatabaseWithRawData:(NSString *_Nonnull)rawHexKey;
- (BOOL)rekeyDatabaseRawDataWithOptions:(NSString *_Nonnull)rawHexKey cipher:(NSString *_Nonnull)cipher iterations:(NSInteger)iterations error:(NSError *_Nullable*_Nullable)error;

// Backup and File Location methods
- (NSString *_Nonnull)databaseDirectory;
- (BOOL)databaseExists;
- (NSString *_Nonnull)pathToDatabase;
- (NSString *_Nonnull)pathToRollbackDatabase;
- (NSString *_Nonnull)pathToRekeyDatabase;
- (BOOL)restoreDatabaseFromRollback:(NSError *_Nullable*_Nullable)error;
- (BOOL)removeRollbackDatabase:(NSError *_Nullable*_Nullable)error;
- (BOOL)restoreDatabaseFromFileAtPath:(NSString *_Nonnull)path error:(NSError *_Nullable*_Nullable)error;
- (BOOL)createReplicaAtPath:(NSString *_Nonnull)path;
- (BOOL)createRollbackDatabase:(NSError *_Nullable*_Nullable)error;
- (BOOL)copyDatabaseToPath:(NSString *_Nonnull)path error:(NSError *_Nullable*_Nullable)error;

// Schema methods
- (NSInteger)getSchemaVersion __attribute__((deprecated)); // DEPRECATED, use schemaVersion dynamic property

// Query / Transaction methods
- (void)execute:(NSString *_Nonnull)sqlCommand; // throws an NSException on command failure
- (BOOL)execute:(NSString *_Nonnull)sqlCommand error:(NSError *_Nullable*_Nullable)error;
- (void)execute:(NSString *_Nonnull)query withBlock:(void (^_Nonnull)(sqlite3_stmt *_Nonnull stmt))block;
- (void)execute:(NSString *_Nonnull)sqlCommand withParams:(NSArray *_Nullable)params;
- (BOOL)execute:(NSString *_Nonnull)sqlCommand error:(NSError *_Nullable*_Nullable)error withParams:(NSArray *_Nullable)params;
- (BOOL)execute:(NSString *_Nonnull)sqlCommand error:(NSError *_Nullable*_Nullable)error withArguments:(NSArray *_Nullable)arguments;
- (void)beginTransaction;
- (void)commitTransaction;
- (void)rollbackTransaction;
- (void)transactionWithBlock:(void(^_Nonnull)(void))block;
- (NSString *_Nullable)getScalar:(NSString *_Nonnull)query;
- (NSString *_Nullable)getScalarWith:(NSString *_Nonnull)query __attribute__((deprecated));
- (NSString *_Nullable)getScalar:(NSString *_Nonnull)query with:(NSArray *_Nullable)params;
- (NSData *_Nullable)getBlobWith:(NSString *_Nonnull)query;
- (NSInteger)countForSQL:(NSString *_Nonnull)countSQL;
- (NSInteger)countForTable:(NSString *_Nonnull)tableName;
- (dispatch_queue_t _Nonnull )serialQueue;
- (void)inQueue:(void (^_Nonnull)(SQLCipherManager *_Nonnull manager))block;
- (void)inQueueAsync:(void (^_Nonnull)(SQLCipherManager *_Nonnull manager))block;


/**
 Runs a SQL query and returns the results as an NSArray, each item of which is an NSArray representing a result row.

 @param SQL Any SQL query
 @param params Optional bind parameters for `SQL` param (supports NSString, NSData, and NSNumber types only)
 @param error If an error occurs it will be supplied to this parameter by reference
 @return An NSArray of rows (NSArray). Array will be empty if no rows are returned, and nil if an error occurs
 */
- (NSArray<NSArray *> *_Nullable)rowsFor:(NSString *_Nonnull)SQL
                                    with:(NSArray *_Nullable)params
                                   error:(NSError *_Nullable*_Nullable)error;

@end

