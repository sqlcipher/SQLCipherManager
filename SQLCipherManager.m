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
+ (NSError *)errorWithSQLitePointer:(char *)errorPointer;
+ (NSError *)errorUsingDatabase:(NSString *)problem reason:(NSString *)dbMessage;
@end

@implementation SQLCipherManager

@synthesize database, inTransaction, delegate, cachedPassword;
@synthesize databaseUrl=_databaseUrl;
@dynamic databasePath;
@synthesize useHMACPageProtection=_useHMACPageProtection;
@dynamic schemaVersion;
@dynamic isDatabaseUnlocked;
@synthesize kdfIterations=_kdfIterations;

static SQLCipherManager *sharedManager = nil;

- (id)init {
    self = [super init];
    if (self) {
        _useHMACPageProtection  = YES;
        _kdfIterations          = 64000;
    }
    return self;
}

- (id)initWithURL:(NSURL *)absoluteUrl
{
    self = [self init];
    if (self)
    {
        _databaseUrl = [absoluteUrl retain];
    }
    return self;
}

- (id)initWithPath:(NSString *)path
{
    NSURL *absoluteURL = [[[NSURL alloc] initFileURLWithPath:path isDirectory:NO] autorelease];
    return [self initWithURL:absoluteURL];
}

- (void)setDatabasePath:(NSString *)databasePath
{
    NSURL *url = [[NSURL alloc] initFileURLWithPath:databasePath isDirectory:NO];
    [self setDatabaseUrl:url];
    [url release];
}

- (NSString *)databasePath
{
    return [[self databaseUrl] path];
}

- (NSNumber *)databaseSize {
	if (!_databaseUrl)
		return nil;
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

+ (NSError *)errorWithSQLitePointer:(char *)errorPointer
{
    NSString *errMsg = [NSString stringWithCString:errorPointer encoding:NSUTF8StringEncoding];
    NSString *description = @"An error occurred executing a SQL statement";
    NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:description, NSLocalizedDescriptionKey, errMsg, NSLocalizedFailureReasonErrorKey, nil];
    return [[[NSError alloc] initWithDomain:SQLCipherManagerErrorDomain 
                                       code:ERR_SQLCIPHER_COMMAND_FAILED 
                                   userInfo:userInfo] 
            autorelease];
}

+ (NSError *)errorUsingDatabase:(NSString *)problem reason:(NSString *)dbMessage
{
	NSString *failureReason = [NSString stringWithFormat:@"DB command failed: '%@'", dbMessage];
	NSArray *objsArray = [NSArray arrayWithObjects: problem, failureReason, nil];
	NSArray *keysArray = [NSArray arrayWithObjects: NSLocalizedDescriptionKey, NSLocalizedFailureReasonErrorKey, nil];
	NSDictionary *userInfo = [NSDictionary dictionaryWithObjects:objsArray forKeys:keysArray];
	return [NSError errorWithDomain:SQLCipherManagerErrorDomain code:ERR_SQLCIPHER_COMMAND_FAILED userInfo:userInfo]; 
}

+ (id)sharedManager {	
	if(!sharedManager)
		sharedManager = [[self alloc] init];
	return sharedManager;
}

+ (void)setSharedManager:(SQLCipherManager *)manager {
  sharedManager = manager;
}

+ (BOOL)passwordIsValid:(NSString *)password  {
	if (password == nil)
		return NO;
	
	// can't be blank a string, either
	if ([[password stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]] length] <= 0)
		return NO;
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
    DLog(@"attempting to open in CFB mode, with 4,000 iterations");
    unlocked = [self openDatabaseWithOptions: password
                                      cipher: @"aes-256-cfb"
                                  iterations: 4000];
    
    if (unlocked == YES) {
        DLog(@"initiating re-key to new settings");
        unlocked = [self rekeyDatabaseWithOptions: password
                                           cipher: @"aes-256-cbc"
                                       iterations: self.kdfIterations
                                            error: &error];
        if (!unlocked && error) {
            DLog(@"error re-keying database: %@", error);
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
            DLog(@"HMAC page protection has been disabled");
            [self execute:@"PRAGMA cipher_default_use_hmac = OFF;" error:NULL];
        } else {
            [self execute:@"PRAGMA cipher_default_use_hmac = ON;" error:NULL];
        }
        
        // submit the password
        const char *key = [password UTF8String];
        sqlite3_key(database, key, strlen(key));
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
            DLog(@"Updating cached password");
            self.cachedPassword = password;
            DLog(@"Calling delegate now that DB is open.");
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
        DLog(@"Ensuring HMAC page protection is on by default for re-key");
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
        DLog(@"Removing older rekey database found on disk");
        [fm removeItemAtPath:[self pathToRekeyDatabase] error:error];
    }
	
	// 2. Attach a re-key database
    NSString *sql = nil;
    // Provide new KEY to ATTACH if not nil
    if (password != nil) {
        sql = [NSString stringWithFormat:@"ATTACH DATABASE '%@' AS rekey KEY '%@';", 
               [self pathToRekeyDatabase], 
               [password stringByReplacingOccurrencesOfString:@"'" withString:@"''"]];
    }
    else {
        // The current key will be used by ATTACH
        sql = [NSString stringWithFormat:@"ATTACH DATABASE '%@' AS rekey;", [self pathToRekeyDatabase]];
    }
    char *errorPointer;
    int rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, &errorPointer);
    if (rc != SQLITE_OK) {
        failed = YES;
        // setup the error object
        NSString *errMsg = [NSString stringWithCString:errorPointer encoding:NSUTF8StringEncoding];
        *error = [SQLCipherManager errorUsingDatabase:@"Unable to attach rekey database" 
                                               reason:errMsg];
        sqlite3_free(errorPointer);
    }
    
	// 2.a rekey cipher
	if (cipher != nil) {
		DLog(@"setting new cipher: %@", cipher);
        sql = [NSString stringWithFormat:@"PRAGMA rekey.cipher='%@';", cipher];
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
		if (rc != SQLITE_OK) {
			failed = YES;
			// setup the error object
			*error = [SQLCipherManager errorUsingDatabase:@"Unable to set rekey.cipher" 
										 reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
		}
	}
	
	// 2.b rekey kdf_iter
	if (failed == NO && iterations > 0) {
		DLog(@"setting new kdf_iter: %d", (int)iterations);
        sql = [NSString stringWithFormat:@"PRAGMA rekey.kdf_iter='%d';", (int)iterations];
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
		if (rc != SQLITE_OK) {
			failed = YES;
			// setup the error object
			*error = [SQLCipherManager errorUsingDatabase:@"Unable to set rekey.kdf_iter"
										 reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
		}
	}
	
    // sqlcipher_export
	if (failed == NO && password) {
		DLog(@"exporting schema and data to rekey database");
		sql = @"SELECT sqlcipher_export('rekey');";
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            failed = YES;
            // setup the error object
			*error = [SQLCipherManager errorUsingDatabase:@"Unable to copy data to rekey database" 
                                                   reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
        }
        // we need to update the user version, too
        NSInteger version = self.schemaVersion;
        sql = [NSString stringWithFormat:@"PRAGMA rekey.user_version = %d;", (int)version];
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            failed = YES;
            // setup the error object
			*error = [SQLCipherManager errorUsingDatabase:@"Unable to set user version" 
                                                   reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
        }
	}
    
    // DETACH rekey database
    if (failed == NO) {
        sql = @"DETACH DATABASE rekey;";
        rc = sqlite3_exec(database, [sql UTF8String], NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            failed = YES;
            // setup the error object
			*error = [SQLCipherManager errorUsingDatabase:@"Unable to detach rekey database" 
                                                   reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
        }
    }
	
    // move the new db into place
	if (failed == NO) {
        // close our current handle to the original db
		[self reallyCloseDatabase];
        
        // move the rekey db into place
        if (![self restoreDatabaseFromFileAtPath:[self pathToRekeyDatabase] error:error]) {
            failed = YES;
        }
        
        // test that our new db works
        if (!([self openDatabaseWithOptions:password
                                     cipher:cipher
                                 iterations:iterations
                                   withHMAC:self.useHMACPageProtection])) {
            failed = YES;
            *error = [SQLCipherManager errorUsingDatabase:@"Unable to open database after moving rekey into place" 
                                                   reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
        }
	}
	
	// if there were no failures...
	if (failed == NO) {
		DLog(@"rekey tested successfully, removing backup file %@", [self pathToRollbackDatabase]);
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
	if (!failed) {
		self.cachedPassword = password;
	}
    
    if (delegate && [delegate respondsToSelector:@selector(sqlCipherManagerDidRekeyDatabase)])
        [delegate sqlCipherManagerDidRekeyDatabase];
	
	return (failed) ? NO : YES;
}

- (void)closeDatabase {
    DLog(@"Closing database");
	sqlite3_close(database);
	database = nil;
}

- (void)reallyCloseDatabase {
    DLog(@"Closing database and checking for SQLITE_BUSY");
	if (sqlite3_close(database) == SQLITE_BUSY) {
        NSLog(@"Warning, database is busy, attempting to interrupt and close...");
		// you're not too busy for us, buddy
		sqlite3_interrupt(database);
		sqlite3_close(database);
	}
	database = nil;
}

- (BOOL)isDatabaseUnlocked {
	if (!database) return NO;
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
#if !TARGET_OS_IPHONE
    // this method just returns YES in iOS, is not implemented
    NSError *error = nil;
    exists = [[self databaseUrl] checkResourceIsReachableAndReturnError:&error];
    if (exists == NO && error != nil) {
        DLog(@"database DNE, error: %@", error);
    }
#else
    NSFileManager *fm = [NSFileManager defaultManager];
    exists = [fm fileExistsAtPath:[[self databaseUrl] path]];
#endif
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
		// remove rollback file
		NSFileManager *fm = [NSFileManager defaultManager];
		[fm removeItemAtPath:[self pathToRollbackDatabase] error:error];
	}
	return success;
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
	DLog(@"removing the file at the primary database path...");
	if ([fm removeItemAtPath:dbPath error:error]) {
		// now move the backup to the original location
		DLog(@"moving the backup file into the primary database path...");
		if ([fm copyItemAtPath:backupPath toPath:dbPath error:error]) {
			return YES;
		}
	}
	return NO;
}

- (BOOL)createReplicaAtPath:(NSString *)path
{
	DLog(@"createReplicaAtPath: %@", path);
	BOOL success = NO;
	sqlite3 *replica = nil;
	if (sqlite3_open([path UTF8String], &replica) == SQLITE_OK) {
		// initialize it with the cached password
		const char *key = [self.cachedPassword UTF8String];
		sqlite3_key(replica, key, strlen(key));
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
    DLog(@"creating a rollback copy of the current database");
    return [self copyDatabaseToPath:[self pathToRollbackDatabase] error:error];
}

- (BOOL)copyDatabaseToPath:(NSString *)path error:(NSError **)error {
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:path]) {
		DLog(@"file already exists at this path, removing...");
		BOOL removed = [fm removeItemAtPath:path error:error];
		if (removed == NO) {
			DLog(@"unable to remove old version of backup database: %@", *error);
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
	if(!inTransaction) {
		[self execute:@"BEGIN;"];
		inTransaction = YES;
	}
}

- (void)commitTransaction {
	if(inTransaction) {
		NSError *error;
		if ([self execute:@"COMMIT;" error:&error]) {
			inTransaction = NO;
		} else {
			NSAssert1(0, @"Fatal database error executing COMMIT command: %@", error);
		}
	}
}

- (void)rollbackTransaction {
	if(inTransaction) {
		NSError *error;
		if ([self execute:@"ROLLBACK;" error:&error]) {
			inTransaction = NO;
		} else {
			NSAssert1(0, @"Fatal database error executing ROLLBACK command: %@", error);
		}
	}
}

- (void)execute:(NSString *)sqlCommand {
    NSError *error;
    if ([self execute:sqlCommand error:&error] != YES) 
    {
        NSException *e = [NSException exceptionWithName:SQLCipherManagerCommandException reason:[error localizedFailureReason] userInfo:[error userInfo]];
        @throw e;
    }
}

- (BOOL)execute:(NSString *)sqlCommand error:(NSError **)error
{
	const char *sql = [sqlCommand UTF8String];
	char *errorPointer;
	if (sqlite3_exec(database, sql, NULL, NULL, &errorPointer) != SQLITE_OK)
	{
		if (error)
		{
            *error = [[self class] errorWithSQLitePointer:errorPointer];
			sqlite3_free(errorPointer);
		}
		return NO;
	}
	return YES;
}

/* FIXME: this should throw (or return from block) an NSException, or an NSError pointer, not NSAssert (crash) */
- (void)execute:(NSString *)query withBlock:(void (^)(sqlite3_stmt *stmt))block
{
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(database, [query UTF8String], -1, &stmt, NULL) == SQLITE_OK) 
	{
		while (sqlite3_step(stmt) == SQLITE_ROW)
		{
			block(stmt);
		}
	}
	else {
		NSAssert1(0, @"Unable to prepare query '%s'", sqlite3_errmsg(database));
	}
	sqlite3_finalize(stmt);
	return;
}

- (NSString *)getScalarWith:(NSString*)query {
	sqlite3_stmt *stmt;
	NSString *scalar = nil;
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
        DLog(@"Error executing SQL: %@", query);
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        [dict setObject:query forKey:SQLCipherManagerUserInfoQueryKey];
        NSString *errorString = [NSString stringWithFormat:@"SQLite error %d: %s", sqlite3_errcode(database), sqlite3_errmsg(database)];
        DLog(@"%@", errorString);
        
        if (inTransaction) {
			NSLog(@"ROLLBACK");
			[self rollbackTransaction];
		}
        
        NSException *e = [NSException exceptionWithName:SQLCipherManagerCommandException reason:errorString userInfo:dict];
        @throw e;
	}
	sqlite3_finalize(stmt);
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

# pragma mark -
# pragma mark Dealloc!
- (void)dealloc {
    [_databaseUrl release];
	if(cachedPassword) {
		memset((void *)[cachedPassword UTF8String], 0, [cachedPassword length]);
	}
	[cachedPassword release];
	[super dealloc];
}

@end
