#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <AuthenticationServices/AuthenticationServices.h>
#import <UIKit/UIKit.h>
#import "fishhook/fishhook.h"

#define BUNDLE_NAME @"Reddit"
#define BUNDLE_ID @"com.reddit.Reddit"
#define TEAM_ID @"2TDUX39LX8"

// https://github.com/opa334/IGSideloadFix

static NSString *keychainAccessGroup;
static NSString *originalKeychainAccessGroup;
static NSURL *fakeGroupContainerURL;

static void createDirectoryIfNotExists(NSURL *URL) {
    if (![URL checkResourceIsReachableAndReturnError:nil]) {
        [[NSFileManager defaultManager] createDirectoryAtURL:URL
                                 withIntermediateDirectories:YES
                                                  attributes:nil
                                                       error:nil];
    }
}

%hook NSBundle

- (NSString *)bundleIdentifier {
    NSArray <NSNumber *>*addresses = NS
