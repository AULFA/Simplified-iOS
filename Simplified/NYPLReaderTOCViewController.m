#import "NYPLConfiguration.h"
#import "NYPLReaderSettings.h"
#import "NYPLReaderTOCCell.h"
#import "NYPLReaderTOCElement.h"
#import "NYPLReadium.h"

#import "NYPLReaderTOCViewController.h"

@interface NYPLReaderTOCViewController () <UITableViewDataSource, UITableViewDelegate>

@property (nonatomic) RDNavigationElement *navigationElement;
@property (nonatomic) UITableView *tableView;
@property (nonatomic) NSArray *TOCElements;

@end

static NSString *const reuseIdentifier = @"ReaderTOCCell";

@implementation NYPLReaderTOCViewController

- (void)generateTOCElementsForNavigationElements:(NSArray *const)navigationElements
                                    nestingLevel:(NSUInteger const)nestingLevel
                                     TOCElements:(NSMutableArray *const)TOCElements
{
  if(!navigationElements.count) return;
  
  for(RDNavigationElement *const navigationElement in navigationElements) {
    NYPLReaderTOCElement *const TOCElement = [[NYPLReaderTOCElement alloc]
                                              initWithNavigationElement:navigationElement
                                              nestingLevel:nestingLevel];
    [TOCElements addObject:TOCElement];
    [self generateTOCElementsForNavigationElements:navigationElement.children
                                      nestingLevel:(nestingLevel + 1)
                                       TOCElements:TOCElements];
  }
}

- (instancetype)initWithNavigationElement:(RDNavigationElement *const)navigationElement
{
  self = [super init];
  if(!self) return nil;
  
  self.title = NSLocalizedString(@"ReaderTOCViewControllerTitle", nil);
  
  self.preferredContentSize = CGSizeMake(320, 1024);
  
  NSMutableArray *const TOCElements = [NSMutableArray array];
  [self generateTOCElementsForNavigationElements:navigationElement.children
                                    nestingLevel:0
                                     TOCElements:TOCElements];
  self.TOCElements = TOCElements;
  
  return self;
}

#pragma mark UIViewController

- (void)viewDidLoad
{
  [super viewDidLoad];
  
  self.tableView = [[UITableView alloc] initWithFrame:self.view.bounds];
  self.tableView.autoresizingMask = (UIViewAutoresizingFlexibleHeight |
                                     UIViewAutoresizingFlexibleWidth);
  self.tableView.backgroundColor = [NYPLConfiguration backgroundColor];
  self.tableView.dataSource = self;
  self.tableView.delegate = self;
  [self.tableView registerClass:[NYPLReaderTOCCell class]
         forCellReuseIdentifier:reuseIdentifier];
  [self.view addSubview:self.tableView];
}

- (void)viewWillAppear:(BOOL const)animated
{
  switch([NYPLReaderSettings sharedSettings].colorScheme) {
    case NYPLReaderSettingsColorSchemeBlackOnSepia:
      self.tableView.backgroundColor = [NYPLConfiguration backgroundSepiaColor];
      break;
    case NYPLReaderSettingsColorSchemeBlackOnWhite:
      self.tableView.backgroundColor = [NYPLConfiguration backgroundColor];
      break;
    case NYPLReaderSettingsColorSchemeWhiteOnBlack:
      self.tableView.backgroundColor = [NYPLConfiguration backgroundDarkColor];
      break;
  }
  
  [self.tableView reloadData];

  [super viewWillAppear:animated];
}

#pragma mark UITableViewDataSource

- (NSInteger)tableView:(__attribute__((unused)) UITableView *)tableView
 numberOfRowsInSection:(__attribute__((unused)) NSInteger)section
{
  return self.TOCElements.count;
}

- (UITableViewCell *)tableView:(__attribute__((unused)) UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *const)indexPath
{
  NYPLReaderTOCCell *const cell = [[NYPLReaderTOCCell alloc]
                                   initWithReuseIdentifier:reuseIdentifier];
  
  NYPLReaderTOCElement *const TOCElement = self.TOCElements[indexPath.row];
  
  cell.nestingLevel = TOCElement.nestingLevel;
  cell.title = TOCElement.navigationElement.title;
  
  return cell;
}

#pragma mark UITableViewDelegate

- (void)tableView:(__attribute__((unused)) UITableView *const)tableView
didSelectRowAtIndexPath:(NSIndexPath *const)indexPath
{
  NYPLReaderTOCElement *const TOCelement = self.TOCElements[indexPath.row];
  
  [self.delegate TOCViewController:self
        didSelectNavigationElement:TOCelement.navigationElement];
}

@end
