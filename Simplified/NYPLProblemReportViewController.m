//
//  NYPLProblemReportViewController.m
//  Simplified
//
//  Created by Sam Tarakajian on 10/29/15.
//  Copyright © 2015 NYPL Labs. All rights reserved.
//

@import MessageUI;

#import <PureLayout/PureLayout.h>
#import "NYPLProblemReportViewController.h"
#import "UIFont+NYPLSystemFontOverride.h"
#import "SimplyE-Swift.h"

static NSArray *s_problems = nil;

@interface NYPLProblemReportViewController () <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) IBOutlet UITableView *problemDescriptionTable;
@property (nonatomic, strong) UIBarButtonItem *submitProblemButton;
@end

@implementation NYPLProblemReportViewController

+ (void)initialize
{
  s_problems = @[
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/wrong-genre",
                   @"title": @"Wrong Genre"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/wrong-audience",
                   @"title": @"Wrong Audience"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/wrong-age-range",
                   @"title": @"Wrong Age Range"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/wrong-title",
                   @"title": @"Wrong Title"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/wrong-medium",
                   @"title": @"Wrong Medium"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/wrong-author",
                   @"title": @"Wrong Author"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/bad-cover-image",
                   @"title": @"Wrong/Missing Cover Image"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/bad-description",
                   @"title": @"Wrong/Mismatched Description"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/cannot-fulfill-loan",
                   @"title": @"Can't Download"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/cannot-issue-loan",
                   @"title": @"Can't Borrow"
                   },
                 @{
                   @"type": @"http://librarysimplified.org/terms/problem/cannot-render",
                   @"title": @"Book Contents Blank or Incorrect"
                   },
                 @{
                   @"type": @"",
                   @"title": @"Other..."
                   },
                 ];
}

- (void)viewDidLoad
{
  [super viewDidLoad];
  
  self.submitProblemButton = [[UIBarButtonItem alloc] initWithTitle:NSLocalizedString(@"Submit", nil)
                                                              style:UIBarButtonItemStyleDone
                                                             target:self action:@selector(submitProblem)];
  self.submitProblemButton.enabled = NO;
  self.navigationItem.rightBarButtonItem = self.submitProblemButton;
  [self.problemDescriptionTable setBackgroundColor:[UIColor whiteColor]];
}

- (void)viewWillAppear:(BOOL)animated
{
  [super viewWillAppear:animated];
  if(self.presentingViewController.traitCollection.horizontalSizeClass == UIUserInterfaceSizeClassRegular) {
    [self.navigationController setNavigationBarHidden:NO];
  }
}

- (void)submitProblem
{
  NSIndexPath *ip = [self.problemDescriptionTable indexPathForSelectedRow];
  if (ip)
    [self.delegate problemReportViewController:self didSelectProblemWithType:s_problems[ip.row][@"type"]];
}

- (void)cancel
{
  if (self.navigationController) {
    [self.navigationController popViewControllerAnimated:YES];
  } else {
    [self dismissViewControllerAnimated:YES completion:nil];
  }
}

- (void)reportIssueVC
{
  Account *currentAcct = [[AccountsManager sharedInstance] currentAccount];
  if ([MFMailComposeViewController canSendMail])
  {
    UIStoryboard *sb = [UIStoryboard storyboardWithName:@"ReportIssue" bundle:nil];
    NYPLReportIssueViewController *vc = [sb instantiateViewControllerWithIdentifier:@"ReportIssueController"];
    vc.account = currentAcct;
    if (self.book) {
      vc.book = self.book;
    }
    vc.completion = ^{
      [self cancel];
    };
    [self.navigationController pushViewController:vc animated:YES];
  }
  else
  {
    UIAlertView *alert = [[UIAlertView alloc]
                          initWithTitle:@"No email account is set for this device. "
                          message:[NSString stringWithFormat:@"If you have web email, contact %@ to report an issue.", currentAcct.supportEmail]
                          delegate:nil
                          cancelButtonTitle:nil
                          otherButtonTitles:@"OK", nil];
    [alert show];
  }
}

#pragma mark UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(__unused UITableView *)tableView
{
  return 1;
}

- (NSInteger)tableView:(__unused UITableView *)tableView numberOfRowsInSection:(__unused NSInteger)section
{
  return s_problems.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
  UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"ProblemReportCell"];
  if (!cell) {
    cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"ProblemReportCell"];
  }
  cell.textLabel.text = s_problems[indexPath.row][@"title"];
  cell.textLabel.font = [UIFont customFontForTextStyle:UIFontTextStyleBody];
  if (indexPath.row == (int)s_problems.count - 1) {
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
  }
  return cell;
}

- (CGFloat)tableView:(__unused UITableView *)tableView heightForRowAtIndexPath:(__unused NSIndexPath *)indexPath
{
  return 44;
}

#pragma mark UITableViewDelegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
  UITableViewCell *cell = [tableView cellForRowAtIndexPath:indexPath];
  
  NSString *typeLabel = s_problems[indexPath.row][@"type"];
  if ([typeLabel isEqualToString:@""]) {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    [self reportIssueVC];
  } else {
    cell.accessoryType = UITableViewCellAccessoryCheckmark;
    if (!self.submitProblemButton.enabled) {
      [self.submitProblemButton setEnabled:YES];
    }
  }
}

- (void)tableView:(UITableView *)tableView didDeselectRowAtIndexPath:(nonnull NSIndexPath *)indexPath
{
  UITableViewCell *cell = [tableView cellForRowAtIndexPath:indexPath];
  cell.accessoryType = UITableViewCellAccessoryNone;
}

@end
