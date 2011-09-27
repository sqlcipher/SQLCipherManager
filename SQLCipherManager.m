//
//  SQLCipherManager.m
//  Strip
//
//  Created by Billy Gray on 12/30/09.
//  Copyright 2009 Zetetic LLC. All rights reserved.
//

#import "SQLCipherManager.h"

#define kSQLCipherRollback @"rollback"

NSString * const SQLCipherManagerErrorDomain = @"SQLCipherManagerErrorDomain";

@interface SQLCipherManager ()
- (void)sendError:(NSString *)error;
+ (NSError *)errorUsingDatabase:(NSString *)problem reason:(NSString *)dbMessage;
@end

@implementation SQLCipherManager

@synthesize database, inTransaction, delegate, cachedPassword;
@synthesize databaseUrl=_databaseUrl;
@dynamic databasePath;

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

+ (NSError *)errorUsingDatabase:(NSString *)problem reason:(NSString *)dbMessage
{
	NSString *failureReason = [NSString stringWithFormat:@"DB command failed: '%@'", dbMessage];
	NSArray *objsArray = [NSArray arrayWithObjects: problem, failureReason, nil];
	NSArray *keysArray = [NSArray arrayWithObjects: NSLocalizedDescriptionKey, NSLocalizedFailureReasonErrorKey, nil];
	NSDictionary *userInfo = [NSDictionary dictionaryWithObjects:objsArray forKeys:keysArray];
	return [NSError errorWithDomain:SQLCipherManagerErrorDomain code:ERR_SQLCIPHER_COMMAND_FAILED userInfo:userInfo]; 
}

+ (id)sharedManager
{
	// static var is initialized at compile time
	static SQLCipherManager *sharedManager = nil;
	
	if(!sharedManager)
		sharedManager = [[self alloc] init];
	return sharedManager;
}

+ (BOOL)passwordIsValid:(NSString *)password  {
	if (password == nil)
		return NO;
	
	// can't be blank a string, either
	if ([[password stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]] length] <= 0)
		return NO;
	return YES; // all clear!
}

- (void) setCachedPassword:(NSString *)password {
	[password retain];
	if(cachedPassword) {
		memset((void *)[cachedPassword UTF8String], 0, [cachedPassword length]);
	}
	[cachedPassword release];
	cachedPassword = password;
}

# pragma mark -
# pragma mark Open, Create, Re-Key and Close Tasks

- (void)createDatabaseWithPassword:(NSString *)password {
	if ([self openDatabaseWithOptions:password cipher:nil iterations:nil]) {
		self.cachedPassword = password;
		if (self.delegate && [self.delegate respondsToSelector:@selector(didCreateDatabase)]) {
			DLog(@"Calling delegate now that db has been created.");
			[self.delegate didCreateDatabase];
		}
	}
}

- (BOOL)openDatabaseWithPassword:(NSString *)password {
	BOOL unlocked = NO;
	/* Code to handle conversion from one cipher and iteration count to another
	 try first opening in the current CBC mode settings. If that fails, try with the CFB mode settings.
	 if that works, then rekey to CBC */
	if (!(unlocked = [self openDatabaseWithOptions:password cipher:@"aes-256-cbc" iterations:@"4000"])) {
		// try again in CFB mode
		if((unlocked = [self openDatabaseWithOptions:password cipher:@"aes-256-cfb" iterations:@"4000"])) {
			// notify the delegate
			if ([delegate respondsToSelector:@selector(sqlCipherManagerWillRekeyDatabase)])
				[delegate sqlCipherManagerWillRekeyDatabase];
			
			unlocked = [self rekeyDatabaseWithOptions:password cipher:@"aes-256-cbc" iterations:@"4000"];
			
			if ([delegate respondsToSelector:@selector(sqlCipherManagerDidRekeyDatabase)])
				[delegate sqlCipherManagerDidRekeyDatabase];
        }
	}
	
	// if unlocked, check to see if there's any needed schema updates
	if(unlocked) {
		self.cachedPassword = password;
		DLog(@"Calling delegate now that DB is open.");
		if (self.delegate && [self.delegate respondsToSelector:@selector(didOpenDatabase)]) { 
			[self.delegate didOpenDatabase];
		}
	} else {
		// close db handle
		[self closeDatabase];
	}
	return unlocked;
}

- (BOOL) openDatabaseWithCachedPassword {
	return [self openDatabaseWithPassword:self.cachedPassword];
}

- (BOOL)openDatabaseWithOptions:(NSString*)password cipher:(NSString*)cipher iterations:(NSString *)iterations {
	BOOL unlocked = NO;
	if (sqlite3_open([[self pathToDatabase] UTF8String], &database) == SQLITE_OK) {
		// submit the password
		const char *key = [password UTF8String];
		sqlite3_key(database, key, strlen(key));
		
		if(cipher) {
			sqlite3_exec(database, (const char*)[[NSString stringWithFormat:@"PRAGMA cipher='%@';", cipher] UTF8String], NULL, NULL, NULL);			
		}
		
		if(iterations) {
			sqlite3_exec(database, (const char*)[[NSString stringWithFormat:@"PRAGMA kdf_iter='%@';", iterations] UTF8String], NULL, NULL, NULL);	
		}
		
		unlocked = [self isDatabaseUnlocked];
        if (!unlocked)
        {
            sqlite3_close(database);
        }
	} else {
		NSAssert1(0, @"Unable to open database file '%s'", sqlite3_errmsg(database));
	}
	return unlocked;
}

- (BOOL)rekeyDatabaseWithPassword:(NSString *)password {
	return [self rekeyDatabaseWithOptions:password cipher:nil iterations:nil];
}

- (BOOL)rekeyDatabaseWithOptions:(NSString*)password cipher:(NSString*)cipher iterations:(NSString *)iterations {	
	// 1. backup current db file
	DLog(@"creating a copy of the current database");
	NSFileManager *fm = [NSFileManager defaultManager];
	NSString *dstPath = [self pathToRollbackDatabase];
	NSError *error = NULL;
	
	if ([fm fileExistsAtPath:dstPath]) {
		DLog(@"backup file already exists, removing...");
		BOOL removed = [fm removeItemAtPath:dstPath error:&error];
		if (removed == NO) {
			DLog(@"unable to remove old version of backup database: %@, %@", [error localizedDescription], [error localizedFailureReason]);
			return NO;
		}
	}
	BOOL copied = [fm copyItemAtPath:[self pathToDatabase] toPath:dstPath error:&error];
	if (copied == NO) {		
		NSLog(@"could not copy database to backup path %@, aborting", dstPath);
		// halt immediatly, can't create a backup
		return NO;
	}
	
	// 2. Initiate the various rekeys
	BOOL failed = NO; // used to track whether any sqlcipher operations have yet failed
	
	// 2.a rekey cipher
	if (cipher) {
		DLog(@"attempting to rekey cipher");
		if (sqlite3_exec(database, (const char*)[[NSString stringWithFormat:@"PRAGMA rekey_cipher='%@';", cipher] UTF8String], NULL, NULL, NULL) != SQLITE_OK) {
			failed = YES;
			// setup the error object
			error = [SQLCipherManager errorUsingDatabase:@"Unable to change database cipher" 
										 reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
		}
	}
	
	// 2.b rekey kdf_iter
	if (failed == NO && iterations) {
		DLog(@"attempting to rekey kdf_iter");
		if (sqlite3_exec(database, (const char*)[[NSString stringWithFormat:@"PRAGMA rekey_kdf_iter='%@';", iterations] UTF8String], NULL, NULL, NULL) != SQLITE_OK) {
			failed = YES;
			// setup the error object
			error = [SQLCipherManager errorUsingDatabase:@"Unable to change database KDF iteration setting"
										 reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
		}
	}
	
	if (failed == NO && password) {
		DLog(@"attempting to rekey password");
		const char* new_key = [(NSString *)password UTF8String];
		if (sqlite3_rekey(database, new_key, strlen(new_key)) != SQLITE_OK) {
			failed = YES;
			// setup the error object
			error = [SQLCipherManager errorUsingDatabase:@"Unable to change database the database password"
										 reason:[NSString stringWithUTF8String:sqlite3_errmsg(database)]];
		}
	}
	
	if (failed == NO) {
		[self closeDatabase]; // close down the database, flush page cache, etc
		if(![self openDatabaseWithOptions:password cipher:cipher iterations:iterations]) {
			failed = YES;
		}
	}
	
	// if there were no failures...
	if (failed == NO) {
		DLog(@"rekey tested successfully, removing backup file %@", dstPath);
		// 3.a. remove backup db file, return YES
		[fm removeItemAtPath:dstPath error:&error];
	} else { // ah, but there were failures...
		// 3.b. close db, replace file with backup
		NSLog(@"rekey test failed, restoring db from backup");
		[self closeDatabase];
		if (![self restoreDatabaseFromRollback:&error]) {
			NSLog(@"Unable to restore database from backup file");
		}
		
		// now this presents an interesting situation... need to let the application/delegate handle this, really
		[delegate didEncounterRekeyError];		
	}
	
	if(error) { // log any errors out to console for us to deal with on support basis
		NSLog(@"error occurred rekeying database: %@, %@", [error localizedDescription], [error localizedFailureReason]);
	}
	
	// if successful, update cached password
	if (!failed) {
		self.cachedPassword = password;
	}
	
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
    NSError *error;
    exists = [[self databaseUrl] checkResourceIsReachableAndReturnError:&error];
    DLog(@"database DNE, error: %@", error);
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

#pragma mark -
#pragma mark Schema methods

- (NSUInteger) getSchemaVersion {
	int version = -1;
	const char *sql = "PRAGMA user_version;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(database, sql, -1, &stmt, NULL) == SQLITE_OK) {
		if (sqlite3_step(stmt) == SQLITE_ROW) {
			version = sqlite3_column_int(stmt, 0);
		} else {
			version = 0;
		}
	} else {
		NSAssert1(0, @"Failed preparing statement to check user_version '%s'", sqlite3_errmsg(database));
	}
	sqlite3_finalize(stmt);
	return version;
}

- (void) setSchemaVersion:(NSInteger)newVersion {
	NSAssert1(newVersion >= 0, @"New version %d is less than zero, only signed integers allowed", newVersion);
	NSString *sql = [NSString stringWithFormat:@"PRAGMA user_version = '%d';", newVersion];
	int rc = sqlite3_exec(database, (const char*) [sql UTF8String], NULL, NULL, NULL);
	
	if(rc != SQLITE_OK) {
		NSAssert1(0, @"Error setting user_version, '%s'", sqlite3_errmsg(database));
	}
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
        // fixme: do a real throw, NSAssert gets squashed in Release
        NSAssert2(0, @"Error executing command '%@', error: %@", sqlCommand, error);
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
			NSString *errMsg = [NSString stringWithCString:errorPointer encoding:NSUTF8StringEncoding];
			NSString *description = @"An error occurred executing the SQL statement";
			NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:description, NSLocalizedDescriptionKey, errMsg, NSLocalizedFailureReasonErrorKey, nil];
			*error = [[[NSError alloc] initWithDomain:SQLCipherManagerErrorDomain code:ERR_SQLCIPHER_COMMAND_FAILED userInfo:userInfo] autorelease];
			sqlite3_free(errorPointer);
		}
		return NO;
	}
	return YES;
}

- (NSString *)getScalarWith:(NSString*)query {
	sqlite3_stmt *stmt;
	NSString *scalar;
	if (sqlite3_prepare_v2(database, [query UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
		if (sqlite3_step(stmt) == SQLITE_ROW) {
			const unsigned char * cValue;
			cValue = sqlite3_column_text(stmt, 0);
			if (cValue) {
				scalar = [NSString stringWithUTF8String:(char *) cValue];
			}
		} 
	} else {
		DLog(@"Error executing SQL: %@", query);
		DLog(@"sqlite3 errorcode: %d", sqlite3_errcode(database));
		DLog(@"sqlite3 errormsg: %s", sqlite3_errmsg(database));
		if (inTransaction) {
			NSLog(@"ROLLBACK");
			[self rollbackTransaction];
		}
		// FIXME: throw an exception here, it's a programmer error if this happens
		NSAssert1(0, @"Error executing command '%@'", query);
	}
	sqlite3_finalize(stmt);
	return scalar;
}

- (NSInteger)countForSQL:(NSString *)countSQL {
	NSInteger count = 0;
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(database, [countSQL UTF8String], -1, &stmt, NULL) == SQLITE_OK) {
		if (sqlite3_step(stmt) == SQLITE_ROW) {
			count = sqlite3_column_int(stmt, 0);
		} // else is still zero
	} else {
		NSAssert1(0, @"Unable to prepare query '%s'", sqlite3_errmsg(database));
	}
	sqlite3_finalize(stmt);
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
