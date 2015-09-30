//
//  SQLCipherManager.m
//  Strip
//
//  Created by Billy Gray on 12/30/09.
//  Copyright 2009 Zetetic LLC. All rights reserved.
//

#import "SQLCipherManager.h"

#define kSQLCipherRollback @"rollback"
#define kSQLCipherRekey @"rekey"

NSString * const SQLCipherManagerErrorDomain = @"SQLCipherManagerErrorDomain";
NSString * const SQLCipherManagerCommandException = @"SQLCipherManagerCommandException";
NSString * const SQLCipherManagerUserInfoQueryKey = @"SQLCipherManagerUserInfoQueryKey";

@interface SQLCipherManager ()
- (void)sendError:(NSString *)error;
+ (NSError *)errorWithSQLitePointer:(const char *)errorPointer;
+ (NSError *)errorUsingDatabase:(NSString *)problem reason:(NSString *)dbMessage;
@end

static const void * const kDispatchQueueSpecificKey = &kDispatchQueueSpecificKey;

@implementation SQLCipherManager

@synthesize database, inTransaction, delegate, cachedPassword;
@synthesize databaseUrl=_databaseUrl;
@dynamic databasePath;
@synthesize useHMACPageProtection=_useHMACPageProtection;
@dynamic schemaVersion;
@dynamic isDatabaseUnlocked;
@synthesize kdfIterations=_kdfIterations;
@synthesize serialQueue=_serialQueue;
@dynamic cipherVersion;
@dynamic cipherProvider;

static SQLCipherManager *sharedManager = nil;

- (id)init {
    self = [super init];
    if (self != nil) {
        _useHMACPageProtection  = YES;
        _kdfIterations          = 64000;
        // set up a serial dispatch queue for database operations
        _serialQueue            = dispatch_queue_create([[NSString stringWithFormat:@"SQLCipher.%@", self] UTF8String], NULL);
        dispatch_queue_set_specific(_serialQueue, kDispatchQueueSpecificKey, (__bridge void *)self, NULL);
    }
    return self;
}

- (id)initWithURL:(NSURL *)absoluteUrl {
    self = [self init];
    if (self != nil) {
        _databaseUrl = [absoluteUrl retain];
    }
    return self;
}

- (id)initWithPath:(NSString *)path {
    NSURL *absoluteURL = [[[NSURL alloc] initFileURLWithPath:path isDirectory:NO] autorelease];
    return [self initWithURL:absoluteURL];
}

- (void)inQueue:(void (^)(SQLCipherManager *manager))block {
    /* Get the currently executing queue (which should probably be nil, but in theory could be another DB queue
     * and then check it against self to make sure we're not about to deadlock. */
    // Credit for this goes to Gus Mueller and his implementation in fmdb/FMDatabaseQueue
    SQLCipherManager *currentManager = (__bridge id)dispatch_get_specific(kDispatchQueueSpecificKey);
    assert(currentManager != self && "inQueue: was called reentrantly on the same queue, which would lead to a deadlock");
    [self retain];
    dispatch_sync(self.serialQueue, ^{
        @autoreleasepool {
            block(self);
        }
    });
    [self release];
}

- (void)inQueueAsync:(void (^)(SQLCipherManager *manager))block {
    /* Get the currently executing queue (which should probably be nil, but in theory could be another DB queue
     * and then check it against self to make sure we're not about to deadlock. */
    // Credit for this goes to Gus Mueller and his implementation in fmdb/FMDatabaseQueue
    SQLCipherManager *currentManager = (__bridge id)dispatch_get_specific(kDispatchQueueSpecificKey);
    assert(currentManager != self && "inQueue: was called reentrantly on the same queue, which would lead to a deadlock");
    [self retain];
    dispatch_async(self.serialQueue, ^{
        @autoreleasepool {
            block(self);
        }
    });
    [self release];
}

- (void)setDatabasePath:(NSString *)databasePath {
    NSURL *url = [[NSURL alloc] initFileURLWithPath:databasePath isDirectory:NO];
    [self setDatabaseUrl:url];
    [url release];
}

- (NSString *)databasePath {
    return [[self databaseUrl] path];
}

- (NSNumber *)databaseSize {
	if (_databaseUrl == nil) {
        return nil;
    }
#if TARGET_OS_IPHONE
    NSError *error;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attrs = [fm attributesOfItemAtPath:[self databasePath] error:&error];
    unsigned long long size = [attrs fileSize];
    NSNumber *fileSize = [NSNumber numberWithUnsignedLongLong: size];
#else
    NSArray *array = [NSArray arrayWithObject:NSURLFileSizeKey];
    NSDictionary *attrs = [_databaseUrl resourceValuesForKeys:array error:NULL];
    NSNumber *fileSize = (NSNumber *)[attrs objectForKey:NSURLFileSizeKey];
#endif
	return fileSize;
}

- (void)sendError:(NSString *)error {
	if (self.delegate && [self.delegate respondsToSelector:@selector(didEncounterDatabaseError:)]) { 
        [self.delegate didEncounterDatabaseError:error];
    }
}

+ (NSError *)errorWithSQLitePointer:(const char *)errorPointer {
    NSString *errMsg = [NSString stringWithCString:errorPointer encoding:NSUTF8StringEncoding];
    NSString *description = @"An error occurred executing a SQL statement";
    NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:description, NSLocalizedDescriptionKey, errMsg, NSLocalizedFailureReasonErrorKey, nil];
    return [[[NSError alloc] initWithDomain:SQLCipherManagerErrorDomain
                                       code:ERR_SQLCIPHER_COMMAND_FAILED
                                   userInfo:userInfo]
            autorelease];
}

+ (NSError *)errorUsingDatabase:(NSString *)problem reason:(NSString *)dbMessage {
	NSString *failureReason = [NSString stringWithFormat:@"DB command failed: '%@'", dbMessage];
	NSArray *objsArray = [NSArray arrayWithObjects: problem, failureReason, nil];
	NSArray *keysArray = [NSArray arrayWithObjects: NSLocalizedDescriptionKey, NSLocalizedFailureReasonErrorKey, nil];
	NSDictionary *userInfo = [NSDictionary dictionaryWithObjects:objsArray forKeys:keysArray];
	return [NSError errorWithDomain:SQLCipherManagerErrorDomain code:ERR_SQLCIPHER_COMMAND_FAILED userInfo:userInfo]; 
}

+ (id)sharedManager {	
	if (sharedManager == nil) {
        sharedManager = [[self alloc] init];
    }
	return sharedManager;
}

+ (void)setSharedManager:(SQLCipherManager *)manager {
  sharedManager = manager;
}

+ (BOOL)passwordIsValid:(NSString *)password  {
	if (password == nil) {
        return NO;
    }
	// can't be blank a string, either
	if ([[password stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]] length] <= 0) {
        return NO;
    }
	return YES; // all clear!
}

- (void)setCachedPassword:(NSString *)password {
    if (cachedPassword != password) {
        NSString *mutableCopy = [password mutableCopy];
        if (cachedPassword != nil) {
            memset((void *)[cachedPassword UTF8String], 0, [cachedPassword length]);
        }
        [cachedPassword release];
        cachedPassword = mutableCopy;
    }
}

# pragma mark -
# pragma mark Open, Create, Re-Key and Close Tasks

- (void)createDatabaseWithPassword:(NSString *)password {
    // just a pass-through, really
	[self openDatabaseWithOptions:password cipher:@"aes-256-cbc" iterations:self.kdfIterations withHMAC:self.useHMACPageProtection];
}

- (BOOL)openDatabaseWithPassword:(NSString *)password {
	BOOL unlocked = NO;
    unlocked = [self openDatabaseWithOptions: password
                                      cipher: @"aes-256-cbc"
                                  iterations: self.kdfIterations
                                    withHMAC: self.useHMACPageProtection];
    return unlocked;
}

- (BOOL)openAndRekeyCFBDatabaseWithPassword:(NSString *)password {
    BOOL unlocked = NO;
    NSError *error;
    NSLog(@"attempting to open in CFB mode, with 4,000 iterations");
    unlocked = [self openDatabaseWithOptions: password
                                      cipher: @"aes-256-cfb"
                                  iterations: 4000];
    
    if (unlocked == YES) {
        NSLog(@"initiating re-key to new settings");
        unlocked = [self rekeyDatabaseWithOptions: password
                                           cipher: @"aes-256-cbc"
                                       iterations: self.kdfIterations
                                            error: &error];
        if (!unlocked && error) {
            NSLog(@"error re-keying database: %@", error);
        }
    }
    return unlocked;
}

- (BOOL)openDatabaseWithCachedPassword {
    return [self openDatabaseWithOptions: self.cachedPassword
                                  cipher: @"aes-256-cbc"
                              iterations: self.kdfIterations
                                withHMAC: YES];
}

- (BOOL)openDatabaseWithOptions:(NSString*)password
                         cipher:(NSString*)cipher
                     iterations:(NSInteger)iterations
                       withHMAC:(BOOL)useHMAC {
    BOOL unlocked = NO;
    BOOL newDatabase = NO;
    if ([self databaseExists] == NO) {
        newDatabase = YES;
    }
    if (sqlite3_open([[self pathToDatabase] UTF8String], &database) == SQLITE_OK) {
        // HMAC page protection is enabled by default in SQLCipher 2.0
        if (useHMAC == NO) {
            NSLog(@"HMAC page protection has been disabled");
            [self execute:@"PRAGMA cipher_default_use_hmac = OFF;" error:NULL];
        } else {
            [self execute:@"PRAGMA cipher_default_use_hmac = ON;" error:NULL];
        }
        // submit the password
        const char *key = [password UTF8String];
        sqlite3_key(database, key, (int)strlen(key));
        // both cipher and kdf_iter must be specified AFTER key
        if (cipher) {
            [self execute:[NSString stringWithFormat:@"PRAGMA cipher='%@';", cipher] error:NULL];
        }
        if (iterations) {
            [self execute:[NSString stringWithFormat:@"PRAGMA kdf_iter='%d';", (int)iterations] error:NULL];
        }
        unlocked = [self isDatabaseUnlocked];
        if (unlocked == NO) {
            sqlite3_close(database);
        } else {
            NSLog(@"Updating cached password");
            self.cachedPassword = password;
            NSLog(@"Calling delegate now that DB is open.");
            if (newDatabase == YES) {
                if (self.delegate && [self.delegate respondsToSelector:@selector(didCreateDatabase)]) {
                    [self.delegate didCreateDatabase];
                }
            } else {
                if (self.delegate && [self.delegate respondsToSelector:@selector(didOpenDatabase)]) {
                    [self.delegate didOpenDatabase];
                }
            }
        }
    } else {
        NSAssert1(0, @"Unable to open database file '%s'", sqlite3_errmsg(database));
    }
    return unlocked;
}

- (BOOL)openDatabaseWithOptions:(NSString*)password
                         cipher:(NSString*)cipher
                     iterations:(NSInteger)iterations {
    return [self openDatabaseWithOptions:password
                                  cipher:cipher
                              iterations:iterations
                                withHMAC:self.useHMACPageProtection];
}

- (BOOL)rekeyDatabaseWithPassword:(NSString *)password {
	return [self rekeyDatabaseWithOptions:password cipher:@"aes-256-cbc" iterations:self.kdfIterations error:NULL];
}

- (BOOL)rekeyDatabaseWithOptions:(NSString*)password 
                          cipher:(NSString*)cipher 
                      iterations:(NSInteger)iterations
                           error:(NSError **)error {
    if (delegate && [delegate respondsToSelector:@selector(sqlCipherManagerWillRekeyDatabase)])
        [delegate sqlCipherManagerWillRekeyDatabase];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL failed = NO; // used to track whether any sqlcipher operations have yet failed
    // if HMAC page protection should be on (e.g. we're doing an upgrade), make it so:
    if (self.useHMACPageProtection) {
        NSLog(@"Ensuring HMAC page protection is on by default for re-key");
        [self execute:@"PRAGMA cipher_default_use_hmac = ON;" error:NULL];
    } else {
        // otherwise, better turn it off for this operation, caller may be looking
        // to create another non-HMAC database
        [self execute:@"PRAGMA cipher_default_use_hmac = OFF;" error:NULL];
    }
	// 1. backup current db file
    BOOL copied = [self createRollbackDatabase:error];
    if (copied == NO) {		
		NSLog(@"could not create rollback database aborting");
		// halt immediatly, can't create a backup
		return NO;
	}
    // make sure there's no older rekey database in the way here
    if ([fm fileExistsAtPath: [self pathToRekeyDatabase]]) {
        NSLog(@"Removing older rekey database found on disk");
        [fm removeItemAtPath:[self pathToRekeyDatabase] error:error];
    }
	// 2. Attach a re-key database
    NSString *sql = nil;
    int rc = 0;
    // Provide new KEY to ATTACH if not nil
    NSError *attachError;
    if (password != nil) {
        sql = @"ATTACH DATABASE ? AS rekey KEY ?;";
        [self execute:sql
                error:&attachError
           withParams:[NSArray arrayWithObjects:[self pathToRekeyDatabase], password, nil]];
    }
    else {
        // The current key will be used by ATTACH
        sql = @"ATTACH DATABASE ? AS rekey;";
        [self execute:sql
                error:&attachError
           withParams:[NSArray arrayWithObjects:[self pathToRekeyDatabase], nil]];
    }
    if (rc != SQLITE_OK) {
        failed = YES;
        // setup the error object
        if (attachError != nil && error != NULL) {
            *error = attachError;
        }
    }
	// 2.a rekey cipher
	if (cipher != nil) {
		NSLog(@"setting new cipher: %@", cipher);
        sql = [NSString stringWithFormat:@"PRAGMA rekey.cipher='%@';", cipher];
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
		if (rc != SQLITE_OK) {
			failed = YES;
			// setup the error object
            if (error != NULL) {
                *error = [SQLCipherManager errorUsingDatabase:@"Unable to set rekey.cipher"
                                                       reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
            }
		}
	}
	// 2.b rekey kdf_iter
	if (failed == NO && iterations > 0) {
		NSLog(@"setting new kdf_iter: %d", (int)iterations);
        sql = [NSString stringWithFormat:@"PRAGMA rekey.kdf_iter='%d';", (int)iterations];
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
		if (rc != SQLITE_OK) {
			failed = YES;
			// setup the error object
            if (error != NULL) {
                *error = [SQLCipherManager errorUsingDatabase:@"Unable to set rekey.kdf_iter"
                                                       reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
            }
		}
	}
    // sqlcipher_export
	if (failed == NO && password) {
		NSLog(@"exporting schema and data to rekey database");
		sql = @"SELECT sqlcipher_export('rekey');";
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            failed = YES;
            // setup the error object
            if (error != NULL) {
                *error = [SQLCipherManager errorUsingDatabase:@"Unable to copy data to rekey database"
                                                       reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
            }
        }
        // we need to update the user version, too
        NSInteger version = self.schemaVersion;
        sql = [NSString stringWithFormat:@"PRAGMA rekey.user_version = %d;", (int)version];
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            failed = YES;
            // setup the error object
            if (error != NULL) {
                *error = [SQLCipherManager errorUsingDatabase:@"Unable to set user version"
                                                       reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
            }
        }
	}
    // DETACH rekey database
    if (failed == NO) {
        sql = @"DETACH DATABASE rekey;";
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            failed = YES;
            // setup the error object
            if (error != NULL) {
                *error = [SQLCipherManager errorUsingDatabase:@"Unable to detach rekey database"
                                                       reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
            }
        }
    }
    // move the new db into place
	if (failed == NO) {
        // close our current handle to the original db
		[self reallyCloseDatabase];
        // move the rekey db into place
        if ([self restoreDatabaseFromFileAtPath:[self pathToRekeyDatabase] error:error] == NO) {
            failed = YES;
        }
        // test that our new db works
        if ([self openDatabaseWithOptions:password
                                     cipher:cipher
                                 iterations:iterations
                                   withHMAC:self.useHMACPageProtection] == NO) {
            failed = YES;
            if (error != NULL) {
                *error = [SQLCipherManager errorUsingDatabase:@"Unable to open database after moving rekey into place"
                                                       reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
            }
        }
	}
	// if there were no failures...
	if (failed == NO) {
		NSLog(@"rekey tested successfully, removing backup file %@", [self pathToRollbackDatabase]);
		// 3.a. remove backup db file, return YES
		[fm removeItemAtPath:[self pathToRollbackDatabase] error:nil];
        // Remove the rekey db, too, since we copied it over
        [fm removeItemAtPath:[self pathToRekeyDatabase] error:nil];
	} else { // ah, but there were failures...
		// 3.b. close db, replace file with backup
		NSLog(@"rekey test failed, restoring db from backup");
		[self closeDatabase];
		if (![self restoreDatabaseFromRollback:error]) {
			NSLog(@"Unable to restore database from backup file");
		}
		// now this presents an interesting situation... need to let the application/delegate handle this, really
		[delegate didEncounterRekeyError];		
	}
	// if successful, update cached password
	if (failed == NO) {
		self.cachedPassword = password;
	}
    if (delegate && [delegate respondsToSelector:@selector(sqlCipherManagerDidRekeyDatabase)]) {
        [delegate sqlCipherManagerDidRekeyDatabase];
    }
	return (failed) ? NO : YES;
}

- (void)closeDatabase {
	sqlite3_close(database);
	database = nil;
}

- (void)reallyCloseDatabase {
	if (sqlite3_close(database) == SQLITE_BUSY) {
        NSLog(@"Warning, database is busy, attempting to interrupt and close...");
		// you're not too busy for us, buddy
		sqlite3_interrupt(database);
		sqlite3_close(database);
	}
	database = nil;
}

- (BOOL)isDatabaseUnlocked {
	if (database == nil) {
        return NO;
    }
	if (sqlite3_exec(database, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL) == SQLITE_OK) {
		return YES;
	}
	return NO;
}

- (BOOL)reopenDatabase:(NSError **)error {
    [self reallyCloseDatabase];
    if ([self openDatabaseWithCachedPassword]) {
        return YES;
    } else {
        if (error != NULL) {
            *error = [[self class] errorUsingDatabase:@"Unable to re-open database" reason:@"Unable to open database with cached password"];
        }
        return NO;
    }
}

# pragma mark -
# pragma mark Backup and file location methods

- (NSString *)databaseDirectory {
	// pass back the parent directory of the user-specified databasePath
	return [[self databasePath] stringByDeletingLastPathComponent];
}

- (BOOL)databaseExists {
    BOOL exists = NO;
    // this method just returns YES in iOS, is not implemented
    NSError *error = nil;
    exists = [[self databaseUrl] checkResourceIsReachableAndReturnError:&error];
    if (exists == NO && error != nil) {
        NSLog(@"Error checking for availability of database file %@, error: %@", [self.databaseUrl path],error);
    }
    return exists;
}

- (NSString *)pathToDatabase {
	return [self databasePath];
}

- (NSString *)pathToRollbackDatabase {
	return [[self databasePath] stringByAppendingPathExtension:kSQLCipherRollback];
}

- (NSString *)pathToRekeyDatabase {
    return [[self databasePath] stringByAppendingPathExtension:kSQLCipherRekey];
}

- (BOOL)restoreDatabaseFromRollback:(NSError **)error {
	BOOL success = [self restoreDatabaseFromFileAtPath:[self pathToRollbackDatabase] error:error];
	if (success) {
		success = [self removeRollbackDatabase:error];
	}
	return success;
}

- (BOOL)removeRollbackDatabase:(NSError **)error {
    NSFileManager *fm = [NSFileManager defaultManager];
    return [fm removeItemAtPath:[self pathToRollbackDatabase] error:error];
}

- (BOOL)restoreDatabaseFromFileAtPath:(NSString *)path error:(NSError **)error {
	NSFileManager *fm = [NSFileManager defaultManager];
	// get the db paths
	NSString *dbPath = [self pathToDatabase];
	NSString *backupPath = path; // argument from caller should be full path to file
	// insist that the two files be present
	NSAssert1([fm fileExistsAtPath:dbPath], @"no db file at %@", dbPath);
	NSAssert1([fm fileExistsAtPath:backupPath], @"no backup db file at %@", backupPath);
	// remove the original to make way for the backup
	NSLog(@"removing the file at the primary database path...");
	if ([fm removeItemAtPath:dbPath error:error]) {
		// now move the backup to the original location
		NSLog(@"moving the backup file into the primary database path...");
		if ([fm copyItemAtPath:backupPath toPath:dbPath error:error]) {
			return YES;
		}
	}
	return NO;
}

- (BOOL)createReplicaAtPath:(NSString *)path {
	BOOL success = NO;
	sqlite3 *replica = nil;
	if (sqlite3_open([path UTF8String], &replica) == SQLITE_OK) {
		// initialize it with the cached password
		const char *key = [self.cachedPassword UTF8String];
		sqlite3_key(replica, key, (int)strlen(key));
		// do a quick check to make sure it took
		if (sqlite3_exec(replica, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL) == SQLITE_OK) {
			success = YES;
		}
	}
	else {
		NSAssert1(0, @"Failed to create replica '%s'", sqlite3_errmsg(replica));
	}
	return success;
}

- (BOOL)createRollbackDatabase:(NSError **)error {
    return [self copyDatabaseToPath:[self pathToRollbackDatabase] error:error];
}

- (BOOL)copyDatabaseToPath:(NSString *)path error:(NSError **)error {
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:path]) {
		BOOL removed = [fm removeItemAtPath:path error:error];
		if (removed == NO) {
			NSLog(@"unable to remove old version of backup database: %@", *error);
			return NO;
		}
	}
    BOOL copied = [fm copyItemAtPath:[self pathToDatabase] toPath:path error:error];
	if (copied == NO) {		
		NSLog(@"could not copy database to path %@: %@", path, *error);
		return NO;
	}
    return YES;
}

#pragma mark -
#pragma mark Schema methods

- (NSString *)cipherVersion {
    return [self getScalarWith:@"PRAGMA cipher_version;"];
}

- (NSString *)cipherProvider {
    return [self getScalarWith:@"PRAGMA cipher_provider;"];
}

- (NSInteger)getSchemaVersion {
    return self.schemaVersion;
}

- (NSInteger)schemaVersion {
    NSString *scalar = [self getScalarWith:@"PRAGMA user_version;"];
    return [scalar integerValue];
}

- (void)setSchemaVersion:(NSInteger)newVersion {
	NSAssert1(newVersion >= 0, @"New version %d is less than zero, only signed integers allowed", (int)newVersion);
    NSString *sql = [NSString stringWithFormat:@"PRAGMA user_version = '%d';", (int)newVersion];
    [self execute:sql];
}

# pragma mark -
# pragma mark Transaction / Query methods
- (void)beginTransaction {
	if (inTransaction == NO) {
		[self execute:@"BEGIN;"];
		inTransaction = YES;
	}
}

- (void)commitTransaction {
	if (inTransaction) {
		NSError *error;
		if ([self execute:@"COMMIT;" error:&error]) {
			inTransaction = NO;
		} else {
			NSAssert1(0, @"Fatal database error executing COMMIT command: %@", error);
		}
	}
}

- (void)rollbackTransaction {
	if (inTransaction) {
		NSError *error;
		if ([self execute:@"ROLLBACK;" error:&error]) {
			inTransaction = NO;
		} else {
			NSAssert1(0, @"Fatal database error executing ROLLBACK command: %@", error);
		}
	}
}

- (void)transactionWithBlock:(void(^)(void))block {
    BOOL outerTransaction = [self inTransaction];
    if (outerTransaction == NO) {
        [self beginTransaction];
    }
    @try {
        block();
        if (outerTransaction == NO) {
            [self commitTransaction];
        }
    }
    @catch (NSException *exception) {
        if (outerTransaction == NO) {
            [self rollbackTransaction];
        }
        @throw exception;
    }
}

- (void)execute:(NSString *)sqlCommand {
    NSError *error;
    if ([self execute:sqlCommand error:&error] != YES) {
        NSException *e = [NSException exceptionWithName:SQLCipherManagerCommandException reason:[error localizedFailureReason] userInfo:[error userInfo]];
        @throw e;
    }
}

- (BOOL)execute:(NSString *)sqlCommand error:(NSError **)error {
	const char *sql = [sqlCommand UTF8String];
	char *errorPointer;
    int rc = sqlite3_exec(database, sql, NULL, NULL, &errorPointer);
	if (rc != SQLITE_OK) {
		if (error != NULL) {
            *error = [[self class] errorWithSQLitePointer:errorPointer];
			sqlite3_free(errorPointer);
		}
		return NO;
	}
	return YES;
}

- (void)execute:(NSString *)query withBlock:(void (^)(sqlite3_stmt *stmt))block {
	sqlite3_stmt *stmt;
    @try {
        if (sqlite3_prepare_v2(database, [query UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                block(stmt);
            }
        }
        else {
            NSAssert1(0, @"Unable to prepare query '%s'", sqlite3_errmsg(database));
        }
    }
    @finally {
        sqlite3_finalize(stmt);
    }
	return;
}

/**
 *  Executes SQL with ? bind parameters. This method throws an NSException on database errors.
 *
 *  @param sqlCommand SQL command string with ? bind parameters
 *  @param NSArray of objects of type NSString, NSData, and NSNumber, exclusively (bound as text, blob, and int, respectively)
 */
- (void)execute:(NSString *)sqlCommand withParams:(NSArray *)params {
    NSError *error;
    BOOL success = [self execute:sqlCommand error:&error withArguments:params];
    if (success == NO) {
        if (error != NULL) {
            NSException *e = [NSException exceptionWithName:SQLCipherManagerCommandException
                                                     reason:[error localizedFailureReason]
                                                   userInfo:[error userInfo]];
            @throw e;
        }
    }
}

- (BOOL)execute:(NSString *)sqlCommand error:(NSError **)error withParams:(NSArray *)params {
    BOOL success = [self execute:sqlCommand error:error withArguments:params];
    return success;
}

- (BOOL)execute:(NSString *)sqlCommand error:(NSError **)error withArguments:(NSArray *)arguments {
    sqlite3_stmt *stmt;
    NSInteger idx = 0;
    BOOL success = YES;
    if (sqlite3_prepare_v2(database, [sqlCommand UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
        // if we have list of params, bind them.
        for (id eachParam in arguments) {
            if ([eachParam isKindOfClass:[NSString class]]) {
                sqlite3_bind_text(stmt, (int)++idx, [eachParam UTF8String], -1, SQLITE_TRANSIENT);
            } else if ([eachParam isKindOfClass:[NSData class]]) {
                sqlite3_bind_blob(stmt, (int)++idx, [eachParam bytes], (int)[eachParam length], SQLITE_STATIC);
            } else { // assume this is an NSNumber int for now...
                // FIXME: add float/decimal support
                sqlite3_bind_int(stmt, (int)++idx, [eachParam intValue]);
            }
        }
        // execute the statement
        int rc = sqlite3_step(stmt);
        // check for errors
        if (rc != SQLITE_DONE) {
            success = NO;
            if (error != NULL) {
                const char *errorMessage = sqlite3_errmsg(database);
                NSError *errorObj = [[self class] errorWithSQLitePointer:errorMessage];
                *error = errorObj;
            }
        }
    } else { // failed to prepare statement
        success = NO;
        if (error != NULL) {
            const char *errorMessage = sqlite3_errmsg(database);
            NSError *errorObj = [[self class] errorWithSQLitePointer:errorMessage];
            *error = errorObj;
        }
    }
    // finalize the statement handle to avoid leaking it
    sqlite3_finalize(stmt);
    return success;
}

- (NSString *)getScalarWith:(NSString*)query {
	sqlite3_stmt *stmt;
    NSString *scalar = nil;
    @try {
        int rc = 0;
        rc = sqlite3_prepare_v2(database, [query UTF8String], -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                const unsigned char * cValue;
                cValue = sqlite3_column_text(stmt, 0);
                if (cValue) {
                    scalar = [NSString stringWithUTF8String:(char *) cValue];
                }
            }
        } else {
            NSMutableDictionary *dict = [NSMutableDictionary dictionary];
            [dict setObject:query forKey:SQLCipherManagerUserInfoQueryKey];
            NSString *errorString = [NSString stringWithFormat:@"SQLite error %d: %s", sqlite3_errcode(database), sqlite3_errmsg(database)];
            if (inTransaction) {
                NSLog(@"ROLLBACK");
                [self rollbackTransaction];
            }
            NSException *e = [NSException exceptionWithName:SQLCipherManagerCommandException reason:errorString userInfo:dict];
            @throw e;
        }
    }
    @finally {
        sqlite3_finalize(stmt);
    }
	return scalar;
}

- (NSInteger)countForSQL:(NSString *)countSQL {
    NSString *scalar = [self getScalarWith:countSQL];
    NSInteger count = [scalar integerValue];
	return count;
}

- (NSInteger)countForTable:(NSString *)tableName {
	return [self countForSQL: [NSString stringWithFormat:@"SELECT COUNT(*) FROM %@;", tableName]];
}

- (void)dealloc {
    dispatch_release(_serialQueue);
    [_databaseUrl release];
	if(cachedPassword) {
		memset((void *)[cachedPassword UTF8String], 0, [cachedPassword length]);
	}
	[cachedPassword release];
	[super dealloc];
}

@end
