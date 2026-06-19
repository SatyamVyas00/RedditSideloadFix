#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <AuthenticationServices/AuthenticationServices.h>
#import <UIKit/UIKit.h>
#import "fishhook/fishhook.h"

#define BUNDLE_NAME @"Reddit"
#define BUNDLE_ID @"com.reddit.Reddit"
#define TEAM_ID @"2TDUX39LX8"

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
    NSArray <NSNumber *>*addresses = NSThread.callStackReturnAddresses;
    Dl_info info;
    if (dladdr((void *)[addresses[2] longLongValue], &info) == 0) return %orig;
    NSString *path = [NSString stringWithUTF8String:info.dli_fname];
    if ([path hasPrefix:NSBundle.mainBundle.bundlePath]) return BUNDLE_ID;
    return %orig;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) return BUNDLE_ID;
    if ([key isEqualToString:@"CFBundleDisplayName"] || [key isEqualToString:@"CFBundleName"])
        return BUNDLE_NAME;
    return %orig;
}

%end

%group SideloadedFixes

%hook NSFileManager

- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier {
    NSURL *fakeURL = [fakeGroupContainerURL URLByAppendingPathComponent:groupIdentifier];
    createDirectoryIfNotExists(fakeURL);
    createDirectoryIfNotExists([fakeURL URLByAppendingPathComponent:@"Library"]);
    createDirectoryIfNotExists([fakeURL URLByAppendingPathComponent:@"Library/Caches"]);
    return fakeURL;
}

%end

static void loadKeychainAccessGroup() {
    NSDictionary *dummyItem = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount : @"dummyItem",
        (__bridge id)kSecAttrService : @"dummyService",
        (__bridge id)kSecReturnAttributes : @YES,
    };
    CFTypeRef result;
    OSStatus ret = SecItemCopyMatching((__bridge CFDictionaryRef)dummyItem, &result);
    if (ret == errSecItemNotFound) ret = SecItemAdd((__bridge CFDictionaryRef)dummyItem, &result);
    if (ret == errSecSuccess && result) {
        NSDictionary *resultDict = (__bridge id)result;
        keychainAccessGroup = resultDict[(__bridge id)kSecAttrAccessGroup];
        originalKeychainAccessGroup =
            [keychainAccessGroup stringByReplacingCharactersInRange:NSMakeRange(0, 10)
                                                        withString:TEAM_ID];
        NSLog(@"RSF: loaded keychainAccessGroup: %@", keychainAccessGroup);
    }
    CFRelease(result);
}

%end

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    if (CFDictionaryContainsKey(attributes, kSecAttrAccessGroup)) {
        CFMutableDictionaryRef mutableAttributes =
            CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, attributes);
        CFDictionarySetValue(mutableAttributes, kSecAttrAccessGroup,
                             (__bridge void *)keychainAccessGroup);
        attributes = CFDictionaryCreateCopy(kCFAllocatorDefault, mutableAttributes);
        CFRelease(mutableAttributes);
    }
    OSStatus status = orig_SecItemAdd(attributes, result);
    if (result && *result && CFGetTypeID(*result) == CFDictionaryGetTypeID() &&
        CFDictionaryContainsKey(*result, kSecAttrAccessGroup)) {
        CFMutableDictionaryRef mutableResult =
            CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, *result);
        CFDictionarySetValue(mutableResult, kSecAttrAccessGroup,
                             (__bridge void *)originalKeychainAccessGroup);
        *result = CFDictionaryCreateCopy(kCFAllocatorDefault, mutableResult);
        CFRelease(mutableResult);
    }
    return status;
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (CFDictionaryContainsKey(query, kSecAttrAccessGroup)) {
        CFMutableDictionaryRef mutableQuery =
            CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, query);
        CFDictionarySetValue(mutableQuery, kSecAttrAccessGroup,
                             (__bridge void *)keychainAccessGroup);
        query = CFDictionaryCreateCopy(kCFAllocatorDefault, mutableQuery);
        CFRelease(mutableQuery);
    }
    OSStatus status = orig_SecItemCopyMatching(query, result);
    if (result && *result && CFGetTypeID(*result) == CFDictionaryGetTypeID() &&
        CFDictionaryContainsKey(*result, kSecAttrAccessGroup)) {
        CFMutableDictionaryRef mutableResult =
            CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, *result);
        CFDictionarySetValue(mutableResult, kSecAttrAccessGroup,
                             (__bridge void *)originalKeychainAccessGroup);
        *result = CFDictionaryCreateCopy(kCFAllocatorDefault, mutableResult);
        CFRelease(mutableResult);
    }
    return status;
}

static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);
static OSStatus hook_SecItemDelete(CFDictionaryRef query) {
    if (CFDictionaryContainsKey(query, kSecAttrAccessGroup)) {
        CFMutableDictionaryRef mutableQuery =
            CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, query);
        CFDictionarySetValue(mutableQuery, kSecAttrAccessGroup,
                             (__bridge void *)keychainAccessGroup);
        query = CFDictionaryCreateCopy(kCFAllocatorDefault, mutableQuery);
        CFRelease(mutableQuery);
    }
    return orig_SecItemDelete(query);
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus hook_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    if (CFDictionaryContainsKey(query, kSecAttrAccessGroup)) {
        CFMutableDictionaryRef mutableQuery =
            CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, query);
        CFDictionarySetValue(mutableQuery, kSecAttrAccessGroup,
                             (__bridge void *)keychainAccessGroup);
        query = CFDictionaryCreateCopy(kCFAllocatorDefault, mutableQuery);
        CFRelease(mutableQuery);
    }
    return orig_SecItemUpdate(query, attributesToUpdate);
}

static void initSideloadedFixes() {
    fakeGroupContainerURL =
        [NSURL fileURLWithPath:[NSHomeDirectory()
                                stringByAppendingPathComponent:@"Documents/FakeGroupContainers"]
                   isDirectory:YES];
    loadKeychainAccessGroup();
    rebind_symbols(
        (struct rebinding[]){
            {"SecItemAdd", (void *)hook_SecItemAdd, (void **)&orig_SecItemAdd},
            {"SecItemCopyMatching", (void *)hook_SecItemCopyMatching,
             (void **)&orig_SecItemCopyMatching},
            {"SecItemDelete", (void *)hook_SecItemDelete, (void **)&orig_SecItemDelete},
            {"SecItemUpdate", (void *)hook_SecItemUpdate, (void **)&orig_SecItemUpdate},
        },
        4);
    %init(SideloadedFixes);
}

static NSString *originalBundleIdentifier;

static void recaptcha_hook(id self, SEL _cmd, id arg) {
    Class cls = object_getClass(self);
    SEL orig_name = NSSelectorFromString([@"orig_" stringByAppendingString:NSStringFromSelector(_cmd)]);
    void (*orig_imp)(id, SEL, id);
    Method method = class_getInstanceMethod(cls, orig_name);
    if (!method) {
        method = class_getClassMethod(cls, orig_name);
        if (method) {
            orig_imp = (void (*)(id, SEL, id))method_getImplementation(method);
            orig_imp(self, orig_name, arg);
        }
        return;
    }
    if ([arg isKindOfClass:NSString.class] &&
        [(NSString *)arg isEqualToString:originalBundleIdentifier])
        arg = BUNDLE_ID;
    orig_imp = (void (*)(id, SEL, id))method_getImplementation(method);
    orig_imp(self, orig_name, arg);
}

static BOOL (*orig_class_addMethod)(Class, SEL, IMP, const char *);
static BOOL hook_class_addMethod(Class cls, SEL name, IMP imp, const char *types) {
    NSString *methodEncoding = [@(types) stringByReplacingOccurrencesOfString:@"[0-9]+"
                                                                   withString:@""
                                                                      options:NSRegularExpressionSearch
                                                                        range:NSMakeRange(0, strlen(types))];
    if ([class_getSuperclass(cls) isEqual:objc_getClass("RCAx_GPBMessage")] &&
        [methodEncoding isEqualToString:@"v@:@"]) {
        if (!orig_class_addMethod(
                cls,
                NSSelectorFromString([@"orig_" stringByAppendingString:NSStringFromSelector(name)]),
                imp, types))
            return orig_class_addMethod(cls, name, imp, types);
        imp = (IMP)recaptcha_hook;
    }
    return orig_class_addMethod(cls, name, imp, types);
}

static void initRecaptchaFix() {
    rebind_symbols((struct rebinding[]){{
        "class_addMethod", (void *)hook_class_addMethod, (void **)&orig_class_addMethod,
    }}, 1);
}

// Login helper — exchanges reddit_session cookie for access token
API_AVAILABLE(ios(13.0))
@interface RSFLoginHelper : NSObject
+ (void)exchangeSessionCookie;
@end

API_AVAILABLE(ios(13.0))
@implementation RSFLoginHelper

+ (void)exchangeSessionCookie {
    // Find reddit_session cookie from web login
    NSArray *cookies = [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies];
    NSString *sessionCookie = nil;
    for (NSHTTPCookie *cookie in cookies) {
        if ([cookie.name isEqualToString:@"reddit_session"] &&
            [cookie.domain containsString:@"reddit.com"]) {
            sessionCookie = cookie.value;
            break;
        }
    }

    if (!sessionCookie) {
        NSLog(@"RSF: No reddit_session cookie found");
        return;
    }

    NSLog(@"RSF: Found reddit_session cookie, exchanging for token...");

    NSURL *url = [NSURL URLWithString:
        @"https://www.reddit.com/auth/v2/oauth/access-token/session"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";

    // Real client ID from Reddit iOS app
    NSString *credentials = @"LNDo9k1o8UAEUw:";
    NSData *credData = [credentials dataUsingEncoding:NSUTF8StringEncoding];
    NSString *b64 = [credData base64EncodedStringWithOptions:0];
    [request setValue:[NSString stringWithFormat:@"Basic %@", b64]
   forHTTPHeaderField:@"Authorization"];

    [request setValue:@"application/json"
   forHTTPHeaderField:@"Content-Type"];
    [request setValue:[NSString stringWithFormat:@"reddit_session=%@", sessionCookie]
   forHTTPHeaderField:@"Cookie"];
    [request setValue:@"Reddit/Version 2026.21.0/Build 630876/iOS Version 16.0 (Build 20A362)"
   forHTTPHeaderField:@"User-Agent"];

    NSData *body = [@"{\"scopes\":[\"*\",\"email\",\"pii\",\"adsread\",\"adsedit\"]}"
                    dataUsingEncoding:NSUTF8StringEncoding];
    request.HTTPBody = body;

    [[NSURLSession.sharedSession dataTaskWithRequest:request
                                  completionHandler:^(NSData *data,
                                                      NSURLResponse *response,
                                                      NSError *error) {
        if (error) {
            NSLog(@"RSF: Token exchange error: %@", error);
            return;
        }
        NSString *responseStr = [[NSString alloc] initWithData:data
                                                      encoding:NSUTF8StringEncoding];
        NSLog(@"RSF: Token exchange response: %@", responseStr);

        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data
                                                             options:0
                                                               error:nil];
        NSString *accessToken = json[@"access_token"];

        if (accessToken) {
            NSLog(@"RSF: Got access token, storing...");
            // Store in keychain so the app picks it up
            NSDictionary *keychainItem = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecAttrService: @"com.reddit.Reddit",
                (__bridge id)kSecAttrAccount: @"access_token",
                (__bridge id)kSecValueData: [accessToken dataUsingEncoding:NSUTF8StringEncoding],
            };
            SecItemDelete((__bridge CFDictionaryRef)keychainItem);
            SecItemAdd((__bridge CFDictionaryRef)keychainItem, nil);

            dispatch_async(dispatch_get_main_queue(), ^{
                [[NSUserDefaults standardUserDefaults] setBool:YES
                                                       forKey:@"RSF_hasLoggedIn"];
                [[NSUserDefaults standardUserDefaults] synchronize];
                // Notify app to refresh auth state
                [[NSNotificationCenter defaultCenter]
                    postNotificationName:UIApplicationDidBecomeActiveNotification
                                  object:nil];
            });
        } else {
            NSLog(@"RSF: No access token in response: %@", responseStr);
        }
    }] resume];
}

@end

// Presentation anchor for ASWebAuthenticationSession
API_AVAILABLE(ios(13.0))
@interface RSFAuthPresenter : NSObject <ASWebAuthenticationPresentationContextProviding>
@end

API_AVAILABLE(ios(13.0))
@implementation RSFAuthPresenter
- (ASPresentationAnchor)presentationAnchorForWebAuthenticationSession:
    (ASWebAuthenticationSession *)session {
    UIWindow *window = nil;
    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            window = scene.windows.firstObject;
            break;
        }
    }
    return window;
}
@end

static id authPresenter;
static id authSession;

static void openSafariLogin(void) {
    if (@available(iOS 13.0, *)) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{

            NSURL *loginURL = [NSURL URLWithString:
                @"https://www.reddit.com/login/?dest=https%3A%2F%2Fwww.reddit.com%2F"];

            authPresenter = [[RSFAuthPresenter alloc] init];

            ASWebAuthenticationSession *session = [[ASWebAuthenticationSession alloc]
                initWithURL:loginURL
                callbackURLScheme:@"reddit"
                completionHandler:^(NSURL *callbackURL, NSError *error) {
                    NSLog(@"RSF: Web login completed, callbackURL: %@, error: %@",
                          callbackURL, error);
                    // Exchange the session cookie for an access token
                    if (@available(iOS 13.0, *)) {
                        [RSFLoginHelper exchangeSessionCookie];
                    }
                }];

            session.presentationContextProvider =
                (id<ASWebAuthenticationPresentationContextProviding>)authPresenter;
            session.prefersEphemeralWebBrowserSession = NO;
            authSession = session;
            [session start];
        });
    }
}

%ctor {
    originalBundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
    %init;
    initSideloadedFixes();
    initRecaptchaFix();

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if (![defaults boolForKey:@"RSF_hasLoggedIn"]) {
        openSafariLogin();
    }
}
