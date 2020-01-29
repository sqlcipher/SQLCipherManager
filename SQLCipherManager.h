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

extern NSString *_Nonnull const SQLCipherManagerCommandException;
extern NSString *_Nonnull const SQLCipherManagerUserInfoQueryKey;

@class SQLCipherManager;

typedef enum : NSUInteger {
    PBKDF2_HMAC_ALGORITHM_DEFAULT,
    PBKDF2_HMAC_ALGORITHM_SHA1,
    PBKDF2_HMAC_ALGORITHM_SHA256,
    PBKDF2_HMAC_ALGORITHM_SHA512,
} PBKDF2_HMAC_ALGORITHM;

typedef enum : NSUInteger {
    HMAC_ALGORITHM_DEFAULT,
    HMAC_ALGORITHM_SHA1,
    HMAC_ALGORITHM_SHA256,
    HMAC_ALGORITHM_SHA512,
} HMAC_ALGORITHM;

NS_ASSUME_NONNULL_BEGIN

@protocol SQLCipherManagerDelegate <NSObject>
@optional
- (void)didOpenDatabase:(SQLCipherManager *)manager;
- (void)didCreateDatabase:(SQLCipherManager *)manager;
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

- (instancetype)initWithURL:(NSURL *)absoluteUrl;
- (instancetype)initWithPath:(NSString *)path; // DEPRECATED
+ (instancetype)sharedManager;
+ (void)setSharedManager:(SQLCipherManager *)manager;
+ (void)clearSharedManager;

+ (BOOL)passwordIsValid:(NSString *)password;

- (NSNumber *_Nullable)databaseSize;

// Open, Close, and Re-Key methods
- (void)createDatabaseWithPassword:(NSString *)password;
- (void)createDatabaseWithPassword:(NSString *)password license:(NSString *_Nullable)licenseKey;
- (BOOL)openDatabaseWithPassword:(NSString *)password;
- (BOOL)openDatabaseWithPassword:(NSString *)password license:(NSString *_Nullable)licenseKey;
- (BOOL)openDatabaseWithCachedPassword;
- (BOOL)openDatabaseWithCachedPasswordAndLicense:(NSString *_Nullable)licenseKey;
- (BOOL)openDatabaseWithOptions:(NSString *)password cipher:(NSString *)cipher iterations:(NSInteger)iterations;
- (BOOL)openDatabaseWithOptions:(NSString *)password cipher:(NSString *)cipher iterations:(NSInteger)iterations withHMAC:(BOOL)useHMAC;
- (BOOL)openDatabaseWithOptions:(NSString *)password cipher:(NSString *)cipher iterations:(NSInteger)iterations withHMAC:(BOOL)useHMAC license:(NSString *_Nullable)licenseKey;
- (BOOL)openDatabaseWithOptions:(NSString *)password cipher:(NSString *)cipher iterations:(NSInteger)iterations withHMAC:(BOOL)useHMAC pageSize:(NSInteger)pageSize license:(NSString *_Nullable)license;
- (BOOL)openDatabaseWithOptions:(NSString *)password cipher:(NSString *)cipher iterations:(NSInteger)iterations withHMAC:(BOOL)useHMAC pageSize:(NSInteger)pageSize kdfAlgo:(PBKDF2_HMAC_ALGORITHM)kdfAlgo license:(NSString *_Nullable)license;
- (BOOL)openDatabaseWithOptions:(NSString *)password cipher:(NSString *)cipher iterations:(NSInteger)iterations withHMAC:(BOOL)useHMAC pageSize:(NSInteger)pageSize kdfAlgo:(PBKDF2_HMAC_ALGORITHM)kdfAlgo hmacAlgo:(HMAC_ALGORITHM)hmacAlgo license:(NSString *_Nullable)license;
- (BOOL)openAndRekeyCFBDatabaseWithPassword:(NSString *)password __attribute__((deprecated));
- (BOOL)rekeyDatabaseWithPassword:(NSString *)password;
- (BOOL)rekeyDatabaseWithOptions:(NSString *)password
                          cipher:(NSString *_Nullable)cipher
                      iterations:(NSInteger)iterations
                           error:(NSError *_Nullable*_Nullable)error;
- (void)closeDatabase;
- (void)reallyCloseDatabase;
- (BOOL)reopenDatabase:(NSError *_Nullable*_Nullable)error;


// Open, Close, and Re-Key using Raw Data
- (void)createDatabaseWithRawData:(NSString *)rawHexKey;
- (void)createDatabaseWithRawData:(NSString *)rawHexKey license:(NSString *_Nullable)licenseKey;
- (BOOL)openDatabaseWithRawData:(NSString *)rawHexKey;
- (BOOL)openDatabaseWithRawData:(NSString *)rawHexKey license:(NSString *_Nullable)licenseKey;
- (BOOL)openDatabaseWithRawData:(NSString *)rawHexKey cipher:(NSString *)cipher withHMAC:(BOOL)useHMAC;
- (BOOL)openDatabaseWithRawData:(NSString *)rawHexKey cipher:(NSString *)cipher withHMAC:(BOOL)useHMAC license:(NSString *_Nullable)licenseKey;
- (BOOL)rekeyDatabaseWithRawData:(NSString *)rawHexKey;
- (BOOL)rekeyDatabaseRawDataWithOptions:(NSString *)rawHexKey cipher:(NSString *)cipher iterations:(NSInteger)iterations error:(NSError *_Nullable*_Nullable)error;

// Backup and File Location methods
- (NSString *)databaseDirectory;
- (BOOL)databaseExists;
- (NSString *)pathToDatabase;
- (NSString *)pathToRollbackDatabase;
- (NSString *)pathToRekeyDatabase;
- (BOOL)restoreDatabaseFromRollback:(NSError *_Nullable*_Nullable)error;
- (BOOL)removeRollbackDatabase:(NSError *_Nullable*_Nullable)error;
- (BOOL)restoreDatabaseFromFileAtPath:(NSString *)path error:(NSError *_Nullable*_Nullable)error;
- (BOOL)createReplicaAtPath:(NSString *)path;
- (BOOL)createRollbackDatabase:(NSError *_Nullable*_Nullable)error;
- (BOOL)copyDatabaseToPath:(NSString *)path error:(NSError *_Nullable*_Nullable)error;

// Schema methods
- (NSInteger)getSchemaVersion __attribute__((deprecated)); // DEPRECATED, use schemaVersion dynamic property

// Query / Transaction methods
- (void)execute:(NSString *)sqlCommand; // throws an NSException on command failure
- (BOOL)execute:(NSString *)sqlCommand error:(NSError *_Nullable*_Nullable)error;
- (void)execute:(NSString *)query withBlock:(void (^)(sqlite3_stmt *stmt))block;
- (void)execute:(NSString *)sqlCommand withParams:(NSArray *_Nullable)params;
- (BOOL)execute:(NSString *)sqlCommand error:(NSError *_Nullable*_Nullable)error withParams:(NSArray *_Nullable)params;
- (BOOL)execute:(NSString *)sqlCommand error:(NSError *_Nullable*_Nullable)error withArguments:(NSArray *_Nullable)arguments;
- (void)beginTransaction;
- (void)commitTransaction;
- (void)rollbackTransaction;
- (void)transactionWithBlock:(void(^)(void))block;
- (NSString *_Nullable)getScalar:(NSString *)query;
- (NSString *_Nullable)getScalarWith:(NSString *)query __attribute__((deprecated));
- (NSString *_Nullable)getScalar:(NSString *)query with:(NSArray *_Nullable)params;
- (NSData *_Nullable)getBlobWith:(NSString *)query;
- (NSInteger)countForSQL:(NSString *)countSQL;
- (NSInteger)countForSQL:(NSString *)countSQL with:(NSArray *)params;
- (NSInteger)countForTable:(NSString *)tableName;
- (dispatch_queue_t)serialQueue;
- (void)inQueue:(void (^)(SQLCipherManager *manager))block;
- (void)inQueueAsync:(void (^)(SQLCipherManager *manager))block;
- (BOOL)tableExists:(NSString *)tableName;

/**
 Runs a SQL query and returns the results as an NSArray, each item of which is an NSArray representing a result row.

 @param SQL Any SQL query
 @param params Optional bind parameters for `SQL` param (supports NSString, NSData, and NSNumber types only)
 @param error If an error occurs it will be supplied to this parameter by reference
 @return An NSArray of rows (NSArray). Array will be empty if no rows are returned, and nil if an error occurs
 */
- (NSArray<NSArray *> *_Nullable)rowsFor:(NSString *)SQL
                                    with:(NSArray *_Nullable)params
                                   error:(NSError *_Nullable*_Nullable)error;


+ (NSError *)errorForResultCode:(NSInteger)resultCode;
+ (NSError *)errorForResultCode:(NSInteger)resultCode reason:(NSString * _Nullable)localizedReason;
+ (NSError *)errorWithDescription:(NSString *)localizedDescription reason:(NSString * _Nullable)localizedReason;

@end

NS_ASSUME_NONNULL_END

