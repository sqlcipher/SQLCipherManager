//
//  ZTSQLCipherManager.h
//  ZTSQLCipherManager
//
//  Created by Billy Gray on 3/23/15.
//
//

#import <UIKit/UIKit.h>
#import <sqlite3.h>

//! Project version number for ZTSQLCipherManager.
FOUNDATION_EXPORT double ZTSQLCipherManagerVersionNumber;

//! Project version string for ZTSQLCipherManager.
FOUNDATION_EXPORT const unsigned char ZTSQLCipherManagerVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <ZTSQLCipherManager/PublicHeader.h>
#import <ZTSQLCipherManager/SQLCipherManager.h>

#ifndef NDEBUG
    #ifndef DLog
        #define DLog(fmt, ...) NSLog((@"%s [Line %d] " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__);
    #endif
#else
    #ifndef DLog
        #define DLog(...) /* */
    #endif
#endif
