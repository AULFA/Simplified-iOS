#import "NYPLReadiumViewSyncManager.h"

#import "NSDate+NYPLDateAdditions.h"
#import "NYPLAccount.h"
#import "NYPLBook.h"
#import "NYPLBookLocation.h"
#import "NYPLBookRegistry.h"
#import "NYPLConfiguration.h"
#import "NYPLJSON.h"
#import "NYPLReachability.h"
#import "NYPLReaderSettings.h"
#import "NYPLRootTabBarController.h"
#import "SimplyE-Swift.h"

typedef NS_ENUM(NSInteger, NYPLReadPositionSyncStatus) {
  NYPLReadPositionSyncStatusIdle,
  NYPLReadPositionSyncStatusBusy
};

@interface NYPLReadiumViewSyncManager ()

@property (nonatomic) NSString *bookID;
@property (nonatomic) NSURL *annotationsURL;
@property (nonatomic) NSDictionary *bookMapDictionary;
@property (nonatomic, weak) id<NYPLReadiumViewSyncManagerDelegate> delegate;
@property (nonatomic) BOOL shouldPostLastRead;
@property (nonatomic) NSString *queuedReadingPosition;
@property (nonatomic) NYPLReadPositionSyncStatus syncStatus;

@end

@implementation NYPLReadiumViewSyncManager

const double RequestTimeInterval = 30;

- (instancetype) initWithBookID:(NSString *)bookID
                 annotationsURL:(NSURL *)URL
                        bookMap:(NSDictionary *)map
                       delegate:(id)delegate
{
  self = [super init];
  if (self) {
    self.bookID = bookID;
    self.annotationsURL = URL;
    self.bookMapDictionary = map;
    self.delegate = delegate;
    self.shouldPostLastRead = NO;
    self.syncStatus = NYPLReadPositionSyncStatusIdle;

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(sendOffAnyQueuedRequest)
                                                 name:UIApplicationWillResignActiveNotification object:nil];
  }
  return self;
}

- (void)dealloc
{
  [self sendOffAnyQueuedRequest];
  [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)syncAllAnnotationsIfAllowedWithPackage:(NSDictionary *)packageDict
{
  if (![NYPLAnnotations syncIsPossibleAndPermitted]) {
    return;
  }

  NSMutableDictionary *const dictionary = [NSMutableDictionary dictionary];
  dictionary[@"package"] = packageDict;
  dictionary[@"settings"] = [[NYPLReaderSettings sharedSettings] readiumSettingsRepresentation];
  NYPLBookLocation *const location = [[NYPLBookRegistry sharedRegistry]
                                      locationForIdentifier:self.bookID];

  [self syncReadingPositionForBook:self.bookID
                        atLocation:location
                             toURL:self.annotationsURL
                       withPackage:dictionary];

  [self syncBookmarksWithCompletion:^(BOOL success, NSArray<NYPLReaderBookmark *> *bookmarks) {
    if ([self.delegate respondsToSelector:@selector(didCompleteBookmarkSync:withBookmarks:)]) {
      [self.delegate didCompleteBookmarkSync:success withBookmarks:bookmarks];
    }
  }];

}

- (void)postLastReadPosition:(NSString *)location
{
  if (!self.shouldPostLastRead) {
    return;
  }

  // Protect against a high frequency of requests to the server
  @synchronized(self) {
    switch (self.syncStatus) {
      case NYPLReadPositionSyncStatusIdle: {
        self.syncStatus = NYPLReadPositionSyncStatusBusy;
        [NYPLAnnotations postReadingPositionForBook:self.bookID annotationsURL:nil cfi:location];
        [NSTimer scheduledTimerWithTimeInterval:RequestTimeInterval
                                         target:self selector:@selector(timerFire) userInfo:nil repeats:NO];
        break;
      }
      case NYPLReadPositionSyncStatusBusy: {
        self.queuedReadingPosition = location;
        break;
      }
    }
  }
}

- (void)timerFire
{
  @synchronized(self) {
    self.syncStatus = NYPLReadPositionSyncStatusIdle;
    if (self.queuedReadingPosition) {
      [self postLastReadPosition:self.queuedReadingPosition];
      self.queuedReadingPosition = nil;
    }
  }
}

- (void)syncReadingPositionForBook:(NSString *)bookID
                        atLocation:(NYPLBookLocation *)location
                             toURL:(NSURL *)URL
                       withPackage:(NSMutableDictionary *)dictionary
{
  [NYPLAnnotations syncReadingPositionOfBook:bookID toURL:URL completionHandler:^(NSDictionary * _Nullable responseObject) {

    // Still on a background thread

    if (!responseObject) {
      NYPLLOG(@"No Server Annotation for this book exists.");
      self.shouldPostLastRead = YES;
      return;
    }

    NSDictionary *responseJSON = [NSJSONSerialization JSONObjectWithData:[responseObject[@"serverCFI"] dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:nil];
    NSString* deviceIDString = responseObject[@"device"];
    NSString* serverLocationString = responseObject[@"serverCFI"];
    NSString* currentLocationString = location.locationString;
    NYPLLOG_F(@"serverLocationString %@",serverLocationString);
    NYPLLOG_F(@"currentLocationString %@",currentLocationString);

    NSDictionary *spineItemDetails = self.bookMapDictionary[responseJSON[@"idref"]];
    NSString *elementTitle = spineItemDetails[@"tocElementTitle"];
    if (!elementTitle) {
      elementTitle = @"";
    }
                
    NSString *message = NSLocalizedString(@"Do you want to move to the page you left off on?", nil);
    if (![elementTitle isEqualToString:@"Current Chapter"]) {
      message = [message stringByAppendingString:[NSString stringWithFormat:@"\n\nChapter:\n\"%@\"", elementTitle]];
    }

    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:NSLocalizedString(@"Sync Reading Position", nil)
                                                                             message:message
                                                                      preferredStyle:UIAlertControllerStyleAlert];

    [alertController addAction:
     [UIAlertAction actionWithTitle:NSLocalizedString(@"NO", nil)
                              style:UIAlertActionStyleCancel
                            handler:^(__attribute__((unused))UIAlertAction * _Nonnull action) {
                              if ([self.delegate respondsToSelector:@selector(patronDecidedNavigation:withNavDict:)]) {
                                [self.delegate patronDecidedNavigation:NO withNavDict:nil];
                              }
                              self.shouldPostLastRead = YES;
                            }]];

    [alertController addAction:
     [UIAlertAction actionWithTitle:NSLocalizedString(@"YES", nil)
                              style:UIAlertActionStyleDefault
                            handler:^(__attribute__((unused))UIAlertAction * _Nonnull action) {

                              self.shouldPostLastRead = YES;

                              NSDictionary *const locationDictionary =
                              NYPLJSONObjectFromData([serverLocationString dataUsingEncoding:NSUTF8StringEncoding]);

                              NSString *contentCFI = locationDictionary[@"contentCFI"];
                              if (!contentCFI) {
                                contentCFI = @"";
                              }
                              dictionary[@"openPageRequest"] =
                              @{@"idref": locationDictionary[@"idref"], @"elementCfi": contentCFI};

                              if ([self.delegate respondsToSelector:@selector(patronDecidedNavigation:withNavDict:)]) {
                                [self.delegate patronDecidedNavigation:YES withNavDict:dictionary];
                              }
                            }]];

    // Pass through without presenting the Alert Controller if:
    // 1 - The most recent page on the server comes from the same device
    // 2 - The server and the client have the same page marked
    // 3 - There is no recent page saved on the server
    if ((currentLocationString && [deviceIDString isEqualToString:[NYPLAccount sharedAccount].deviceID]) ||
      [currentLocationString isEqualToString:serverLocationString] ||
      !serverLocationString) {
      self.shouldPostLastRead = YES;
    } else {
      [[NSOperationQueue mainQueue] addOperationWithBlock:^{
        [[NYPLRootTabBarController sharedController] safelyPresentViewController:alertController animated:YES completion:nil];
      }];
    }
  }];
}

- (void)addBookmark:(NYPLReaderBookmark *)bookmark
            withCFI:(NSString *)location
            forBook:(NSString *)bookID
{
  Account *currentAccount = [[AccountsManager sharedInstance] currentAccount];
  if (currentAccount.syncPermissionGranted) {
    [NYPLAnnotations postBookmarkForBook:bookID toURL:nil bookmark:bookmark
                       completionHandler:^(NSString * _Nullable serverAnnotationID) {
                         if (serverAnnotationID) {
                           NYPLLOG_F(@"Bookmark upload success: %@", location);
                         } else {
                           NYPLLOG_F(@"Bookmark failed to upload: %@", location);
                         }
                         bookmark.annotationId = serverAnnotationID;
                         [self.delegate uploadFinishedForBookmark:bookmark inBook:bookID];
                       }];
  } else {
    [self.delegate uploadFinishedForBookmark:bookmark inBook:bookID];
    NYPLLOG(@"Bookmark saving locally. Sync is not enabled for account.");
  }
}

- (void)syncBookmarksWithCompletion:(void(^)(BOOL success, NSArray<NYPLReaderBookmark *> *bookmarks))completion
{
  [[NYPLReachability sharedReachability]
   reachabilityForURL:[NYPLConfiguration mainFeedURL]
   timeoutInternal:8.0
   handler:^(BOOL reachable) {

     if (!reachable) {
       NYPLLOG(@"Error: host was not reachable for bookmark sync attempt.");
       completion(NO, [[NYPLBookRegistry sharedRegistry] bookmarksForIdentifier:self.bookID]);
       return;
     }

     // Sync: First upload any local bookmarks that have never been saved to the server.
     // Then download the server's bookmark list and filter out any that can be deleted.

     NSArray<NYPLReaderBookmark *> *localBookmarks = [[NYPLBookRegistry sharedRegistry] bookmarksForIdentifier:self.bookID];
     NYPLLOG_F(@"\nLocally Saved Bookmarks:\n\n%@", localBookmarks);
     
     [NYPLAnnotations uploadLocalBookmarks:localBookmarks forBook:self.bookID completion:^(NSArray<NYPLReaderBookmark *> * _Nonnull bookmarksUploaded, NSArray<NYPLReaderBookmark *> * _Nonnull bookmarksFailedToUpload) {

       NYPLLOG_F(@"\nBookmarks First Time Uploaded:\n\n%@", bookmarksUploaded);
       NYPLLOG_F(@"\nBookmarks Failed To Upload:\n\n%@", bookmarksFailedToUpload);

       // Replace local bookmarks with server versions
       for (NYPLReaderBookmark *localBKM in localBookmarks) {
         for (NYPLReaderBookmark *uploadedBKM in bookmarksUploaded) {
           if ([localBKM isEqual:uploadedBKM]) {
             [[NYPLBookRegistry sharedRegistry] deleteBookmark:localBKM forIdentifier:self.bookID];
             [[NYPLBookRegistry sharedRegistry] addBookmark:uploadedBKM forIdentifier:self.bookID];
           }
         }
       }

       [NYPLAnnotations getServerBookmarksForBook:self.bookID atURL:self.annotationsURL completionHandler:^(NSArray<NYPLReaderBookmark *> * _Nonnull serverBookmarks) {

         if (serverBookmarks.count == 0) {
           NYPLLOG(@"No server bookmarks were returned.");
         } else {
           NYPLLOG_F(@"\nServer Bookmarks:\n\n%@", serverBookmarks);
         }

         NSMutableArray<NYPLReaderBookmark *> *localBookmarksToKeep = [[NSMutableArray alloc] init];
         NSMutableArray<NYPLReaderBookmark *> *localBookmarksToDelete = [[NSMutableArray alloc] init];
         NSMutableArray<NYPLReaderBookmark *> *serverBookmarksToKeep = serverBookmarks.mutableCopy;
         NSMutableArray<NYPLReaderBookmark *> *serverBookmarksToDelete = [[NSMutableArray alloc] init];

         for (NYPLReaderBookmark *serverBookmark in serverBookmarks) {
           NSPredicate *predicate = [NSPredicate predicateWithFormat:@"annotationId == %@", serverBookmark.annotationId];
           NSArray *matchingBookmarks = [localBookmarks filteredArrayUsingPredicate:predicate];

           [localBookmarksToKeep addObjectsFromArray:matchingBookmarks];

           // Server bookmarks, created on this device, that are no longer present as a local bookmark,
           // should be deleted on the server.
           if (matchingBookmarks.count == 0 &&
               [serverBookmark.device isEqualToString:[[NYPLAccount sharedAccount] deviceID]]) {
             [serverBookmarksToDelete addObject:serverBookmark];
             [serverBookmarksToKeep removeObject:serverBookmark];
           }
         }

         for (NYPLReaderBookmark *localBookmark in localBookmarks) {
           if (![localBookmarksToKeep containsObject:localBookmark]) {
             [[NYPLBookRegistry sharedRegistry] deleteBookmark:localBookmark forIdentifier:self.bookID];
             [localBookmarksToDelete addObject:localBookmark];
           }
         }
         NYPLLOG_F(@"\nBookmarks To Delete From Registry:\n\n%@", localBookmarksToDelete);

         NSMutableArray<NYPLReaderBookmark *> *bookmarksToAdd = serverBookmarks.mutableCopy;
         [bookmarksToAdd addObjectsFromArray:bookmarksFailedToUpload];

         for (NYPLReaderBookmark *serverMark in serverBookmarksToKeep) {
           for (NYPLReaderBookmark *localMark in localBookmarksToKeep) {
             if ([serverMark isEqual:localMark]) {
               [bookmarksToAdd removeObject:localMark];
             }
           }
         }
         NYPLLOG_F(@"\nBookmarks To Save To Registry:\n\n%@", bookmarksToAdd);

         for (NYPLReaderBookmark *bookmark in bookmarksToAdd) {
           [[NYPLBookRegistry sharedRegistry] addBookmark:bookmark forIdentifier:self.bookID];
         }

         if (serverBookmarksToDelete.count > 0) {
           NYPLLOG_F(@"\nBookmarks to Delete from the Server:\n\n%@", serverBookmarksToDelete);
           [NYPLAnnotations deleteBookmarks:serverBookmarksToDelete completionHandler:^{
             completion(YES,[[NYPLBookRegistry sharedRegistry] bookmarksForIdentifier:self.bookID]);
           }];
         } else {
           completion(YES,[[NYPLBookRegistry sharedRegistry] bookmarksForIdentifier:self.bookID]);
         }
       }];
     }];
   }];
}

- (void)sendOffAnyQueuedRequest
{
  if (self.queuedReadingPosition) {
    [NYPLAnnotations postReadingPositionForBook:self.bookID annotationsURL:nil cfi:self.queuedReadingPosition];
    self.queuedReadingPosition = nil;
  }
}

@end