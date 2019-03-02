project 'Simplified.xcodeproj'

# Uncomment this line to define a global platform for your project
platform :ios, '8.0'

inhibit_all_warnings!

target 'LFA' do

  use_frameworks!

  pod 'HelpStack', :git => 'https://github.com/NYPL-Simplified/helpstack-ios'
  pod 'Bugsnag', '~> 5.14.2'
  pod 'NYPLCardCreator', :git => 'https://github.com/NYPL-Simplified/CardCreator-iOS.git'
  pod 'SQLite.swift', '~> 0.11.4'
  pod 'ZXingObjC', '~> 3.2.1'

  target 'LFATests' do
    inherit! :search_paths
  end
end


