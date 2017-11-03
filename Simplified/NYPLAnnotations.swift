import UIKit

//  NYPLAnnotations.swift
//  GODO Add class description
final class NYPLAnnotations: NSObject {


  // THis first method may be completely unneeded if we're just letting a user pick their preference on each device.
  class func getPermissionStatusFromServer(completionHandler: @escaping (_ initialized: Bool, _ value:Bool) -> ()) {

    //GODO AccountsManager.shared.currentAccount.supportsSimplyESync - should it be Current Account or should it be whatever account you're in the Settings Detail for?
    if (NYPLAccount.shared().hasBarcodeAndPIN() && AccountsManager.shared.currentAccount.supportsSimplyESync) {

      guard let annotationSettingsUrl = NYPLConfiguration.mainFeedURL()?.appendingPathComponent("patrons/me/") else {
        Log.error(#file, "Failed to create Annotations URL. Abandoning attempt to retrieve sync setting.")
        return
      }
      var request = URLRequest.init(url: annotationSettingsUrl, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
      request.httpMethod = "GET"
      setDefaultAnnotationHeaders(forRequest: &request)

      let dataTask = URLSession.shared.dataTask(with: request) { (data, response, error) in

        if let error = error as NSError? {
          Log.error(#file, "Request Error Code: \(error.code). Description: \(error.localizedDescription)")
          return
        }
        guard let data = data,
        let response = (response as? HTTPURLResponse) else {
          Log.error(#file, "No Data or No Server Response present after request.")
          return
        }

        if response.statusCode == 200 {
          if let json = try? JSONSerialization.jsonObject(with: data, options: []) as! [String:Any],
          let settings = json["settings"] as? [String:Any],
          let syncSetting = settings["simplified:synchronize_annotations"] {
            if syncSetting is NSNull {
              completionHandler(false, false)
            } else {
              completionHandler(true, syncSetting as? Bool ?? false)
            }
          } else {
            Log.error(#file, "Error parsing JSON or finding sync-setting key/value.")
          }
        } else {
          Log.error(#file, "Server response returned error code: \(response.statusCode))")
        }
      }
      dataTask.resume()
    }
  }
  
  class func updateSyncSettings(_ synchronize_annotations:Bool) {
    if (NYPLAccount.shared().hasBarcodeAndPIN() &&
      AccountsManager.shared.currentAccount.supportsSimplyESync) {
      guard let annotationSettingsUrl = NYPLConfiguration.mainFeedURL()?.appendingPathComponent("patrons/me/") else {
        Log.error(#file, "Could not create Annotations URL from Main Feed URL. Abandoning attempt to update sync setting.")
        return
      }
      let parameters = ["settings": ["simplified:synchronize_annotations": synchronize_annotations]] as [String : Any]
      putSyncSettingsJSONRequest(annotationSettingsUrl, parameters)
    }
  }
  
  private class func putSyncSettingsJSONRequest(_ url: URL,
                                                _ parameters: [String:Any]) {
    guard let jsonData = try? JSONSerialization.data(withJSONObject: parameters, options: [.prettyPrinted]) else {
      Log.error(#file, "Network request abandoned. Could not create JSON from given parameters.")
      return
    }
    
    var request = URLRequest(url: url)
    request.httpMethod = "PUT"
    request.httpBody = jsonData
    setDefaultAnnotationHeaders(forRequest: &request)
    request.setValue("vnd.librarysimplified/user-profile+json", forHTTPHeaderField: "Content-Type")
    
    let task = URLSession.shared.dataTask(with: request) { (data, response, error) in

      if let error = error as NSError? {
        Log.error(#file, "Request Error Code: \(error.code). Description: \(error.localizedDescription)")
        if NetworkQueue.StatusCodes.contains(error.code) {
          self.addToOfflineQueue(nil, url, parameters)
        }
        return
      }
      guard let statusCode = (response as? HTTPURLResponse)?.statusCode else {
        Log.error(#file, "No response received from server")
        return
      }

      if statusCode == 200 {
        //          {
        //            "simplified:authorization_expires": "2020-03-16T00:00:00Z",
        //            "settings": {
        //              "simplified:synchronize_annotations": true
        //            }
        //          }
      } else {
        Log.error(#file, "Server Response Error. Status Code: \(statusCode)")
      }
    }
    task.resume()
  }
  
  class func syncLastRead(_ book:NYPLBook,
                          completionHandler: @escaping (_ responseObject: [String:String]?) -> ()) {
    
    if (NYPLAccount.shared().hasBarcodeAndPIN() && book.annotationsURL != nil  &&
      AccountsManager.shared.currentAccount.supportsSimplyESync) {

      var request = URLRequest.init(url: book.annotationsURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
      request.httpMethod = "GET"
      setDefaultAnnotationHeaders(forRequest: &request)
      
      let dataTask = URLSession.shared.dataTask(with: request) { (data, response, error) in
        
        if let error = error as NSError? {
          Log.error(#file, "Request Error Code: \(error.code). Description: \(error.localizedDescription)")
          completionHandler(nil)
          return
        }
        guard let data = data,
          let json = try? JSONSerialization.jsonObject(with: data, options: []) as! [String:Any] else {
            Log.error(#file, "JSON could not be created from data, or data was nil.")
            completionHandler(nil)
            return
        }
        if let total = json["total"] as? Int {
          if total <= 0 {
            Log.error(#file, "\"total\" key was empty")
            completionHandler(nil)
            return
          }
        }
        guard let first = json["first"] as? [String:AnyObject],
          let items = first["items"] as? [AnyObject] else {
            completionHandler(nil)
            return
        }

        for item in items {
          guard let target = item["target"] as? [String:AnyObject],
            let source = target["source"] as? String,
            let motivation = item["motivation"] as? String else {
              completionHandler(nil)
              return
          }

          if source == book.identifier && motivation == "http://librarysimplified.org/terms/annotation/idling" {

            guard let selector = target["selector"] as? [String:AnyObject],
              let serverCFI = selector["value"] as? String else {
                completionHandler(nil)
                return
            }

            var responseObject = ["serverCFI" : serverCFI]

            if let body = item["body"] as? [String:AnyObject],
              let device = body["http://librarysimplified.org/terms/device"] as? String,
              let time = body["http://librarysimplified.org/terms/time"] as? String {
              responseObject["device"] = device
              responseObject["time"] = time
            }

            completionHandler(responseObject)
            return
          }
        }
      }
      dataTask.resume()
    }
  }
  
  class func postLastRead(_ book:NYPLBook,
                          cfi:NSString) {

    //GODO need to update the conditionals
    if (NYPLAccount.shared().hasBarcodeAndPIN() && AccountsManager.shared.currentAccount.supportsSimplyESync &&
      AccountsManager.shared.currentAccount.syncPermissionGranted) {
      let parameters = [
        "@context": "http://www.w3.org/ns/anno.jsonld",
        "type": "Annotation",
        "motivation": "http://librarysimplified.org/terms/annotation/idling",
        "target":[
          "source":  book.identifier,
          "selector": [
            "type": "oa:FragmentSelector",
            "value": cfi
          ]
        ],
        "body": [
          "http://librarysimplified.org/terms/time" : NSDate().rfc3339String(),
          "http://librarysimplified.org/terms/device" : NYPLAccount.shared().deviceID
        ]
        ] as [String : Any]
      
      if let annotationsUrl = NYPLConfiguration.mainFeedURL()?.appendingPathComponent("annotations/") {
        postAnnotationJSONRequest(book, annotationsUrl, parameters, completionHandler: { success in
          Log.debug(#file, "Successfully posted last reading position.")
        })
      } else {
        Log.error(#file, "MainFeedURL does not exist")
      }
    }
  }
  
  private class func postAnnotationJSONRequest(_ book: NYPLBook,
                                               _ url: URL,
                                               _ parameters: [String:Any],
                                               completionHandler: @escaping (_ success: Bool) -> ()) {

    guard let jsonData = try? JSONSerialization.data(withJSONObject: parameters, options: [.prettyPrinted]) else {
      Log.error(#file, "Network request abandoned. Could not create JSON from given parameters.")
      return
    }
    
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.httpBody = jsonData
    setDefaultAnnotationHeaders(forRequest: &request)
    
    let task = URLSession.shared.dataTask(with: request) { (data, response, error) in

      if let error = error as NSError? {
        Log.error(#file, "Request Error Code: \(error.code). Description: \(error.localizedDescription)")
        if NetworkQueue.StatusCodes.contains(error.code) {
          self.addToOfflineQueue(book, url, parameters)
        }
        completionHandler(false)
      }
      guard let statusCode = (response as? HTTPURLResponse)?.statusCode else {
        Log.error(#file, "No response received from server")
        completionHandler(false)
        return
      }

      if statusCode == 200 {
        Log.debug(#file, "Posted Last-Read \(((parameters["target"] as! [String:Any])["selector"] as! [String:Any])["value"] as! String)")
        completionHandler(true)
      } else {
        Log.error(#file, "Server Response Error. Status Code: \(statusCode)")
        completionHandler(false)
      }
    }
    task.resume()
  }

  //GODO need to test this method
  class func getBookmark(_ book:NYPLBook,
                         _ cfi:NSString,
                         completionHandler: @escaping (_ responseObject: NYPLReaderBookmarkElement?) -> ()) {
    
    guard let data = cfi.data(using: String.Encoding.utf8.rawValue),
      let responseJSON = try? JSONSerialization.jsonObject(with: data,
      options: JSONSerialization.ReadingOptions.mutableContainers) as! [String:Any] else {
        Log.error(#file, "Error creating JSON Object")
        return
    }
    guard let localContentCfi = responseJSON["contentCFI"] as? String,
      let localIdref = responseJSON["idref"] as? String else {
        Log.error(#file, "Could not get contentCFI or idref from responseJSON")
        return
    }

    getBookmarks(book) { bookmarks in
      completionHandler(bookmarks
        .filter({ $0.contentCFI == localContentCfi && $0.idref == localIdref })
        .first)
    }
  }
  
  class func getBookmarks(_ book:NYPLBook, completionHandler: @escaping (_ bookmarks: [NYPLReaderBookmarkElement]) -> ()) {
    
    var bookmarks = [NYPLReaderBookmarkElement]()

    //GODO double check these conditionals at the callsites. example: there are no conditionals in getBookmark() .. is that wrong?
    if (NYPLAccount.shared().hasBarcodeAndPIN() && book.annotationsURL != nil &&
      AccountsManager.shared.currentAccount.supportsSimplyESync) {

      var request = URLRequest.init(url: book.annotationsURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
      request.httpMethod = "GET"
      setDefaultAnnotationHeaders(forRequest: &request)
      
      let dataTask = URLSession.shared.dataTask(with: request) { (data, response, error) in
        
        if let error = error as NSError? {
          Log.error(#file, "Request Error Code: \(error.code). Description: \(error.localizedDescription)")
          completionHandler(bookmarks)
          return
        }
        guard let data = data,
          let json = try? JSONSerialization.jsonObject(with: data, options: []) as! [String:Any] else {
            Log.error(#file, "JSON could not be created from data.")
            completionHandler(bookmarks)
            return
        }
        if let total = json["total"] as? Int {
          if total <= 0 {
            Log.error(#file, "\"total\" key was empty")
            return
          }
        }
        guard let first = json["first"] as? [String:AnyObject],
          let items = first["items"] as? [AnyObject] else {
            completionHandler(bookmarks)
            return
        }

        for item in items {
          if let bookmark = createBookmarkElement(book, item) {
            bookmarks.append(bookmark)
          } else {
            Log.error(#file, "Could not create bookmark element from item.")
            continue
          }
        }
        completionHandler(bookmarks)
      }
      dataTask.resume()
    }
  }

  private class func createBookmarkElement(_ book: NYPLBook, _ item: AnyObject) -> NYPLReaderBookmarkElement? {

    guard let target = item["target"] as? [String:AnyObject],
    let source = target["source"] as? String,
    let id = item["id"] as? String,
    let motivation = item["motivation"] as? String else {
      Log.error(#file, "Error parsing key/values for target.")
      return nil
    }

    if source == book.identifier && motivation.contains("bookmarking") {

      guard let selector = target["selector"] as? [String:AnyObject],
        let serverCFI = selector["value"] as? String,
        let body = item["body"] as? [String:AnyObject] else {
          Log.error(#file, "ServerCFI could not be parsed.")
          return nil
      }

      guard let device = body["http://librarysimplified.org/terms/device"] as? String,
      let time = body["http://librarysimplified.org/terms/time"] as? String,
      let progressWithinChapter = body["http://librarysimplified.org/terms/progressWithinChapter"] as? Float,
      let progressWithinBook = body["http://librarysimplified.org/terms/progressWithinBook"] as? Float else {
        Log.error(#file, "Error reading required bookmark key/values from body")
        return nil
      }
      let chapter = body["http://librarysimplified.org/terms/chapter"] as? String

      guard let data = serverCFI.data(using: String.Encoding.utf8),
        let serverCfiJsonObject = try? JSONSerialization.jsonObject(with: data,
          options: JSONSerialization.ReadingOptions.mutableContainers) as! [String:String],
        let serverCfiJson = serverCfiJsonObject["contentCFI"],
        let serverIdrefJson = serverCfiJsonObject["idref"] else {
          Log.error(#file, "Error serializing serverCFI into JSON.")
          return nil
      }

      //GODO which parameters are optional and which are required?
      // for now i'm assuming that any of hte parameters that were being forced unwrapped are required
      //can change the factory method and let those optionals percolate through instead of all this nonsense here
      let bookmark = NYPLReaderBookmarkElement(annotationId: id,
                                               contentCFI: serverCfiJson,
                                               idref: serverIdrefJson,
                                               chapter: chapter ?? "",
                                               page: nil,
                                               location: serverCFI,
                                               progressWithinChapter: progressWithinChapter,
                                               progressWithinBook: progressWithinBook)
      bookmark.time = time
      bookmark.device = device
      return bookmark
    } else {
      Log.error(#file, "'source' key/value does not match current NYPLBook object ID, or 'motivation' key/value is invalid.")
    }
    return nil
  }
  
  class func postBookmark(_ book:NYPLBook,
                          cfi:NSString,
                          bookmark:NYPLReaderBookmarkElement,
                          completionHandler: @escaping (_ responseObject: NYPLReaderBookmarkElement?) -> ())
  {
    //GODO all these need to be re-thought supportsSimplyESync, syncIsEnabled, etc. etc.
    if (NYPLAccount.shared().hasBarcodeAndPIN() && AccountsManager.shared.currentAccount.supportsSimplyESync) {
      let parameters = [
        "@context": "http://www.w3.org/ns/anno.jsonld",
        "type": "Annotation",
        "motivation": "http://www.w3.org/ns/oa#bookmarking",
        "target":[
          "source":  book.identifier,
          "selector": [
            "type": "oa:FragmentSelector",
            "value": cfi
          ]
        ],
        "body": [
          "http://librarysimplified.org/terms/time" : NSDate().rfc3339String(),
          "http://librarysimplified.org/terms/device" : NYPLAccount.shared().deviceID,
          "http://librarysimplified.org/terms/chapter" : bookmark.chapter!,
          "http://librarysimplified.org/terms/progressWithinChapter" : bookmark.progressWithinChapter,
          "http://librarysimplified.org/terms/progressWithinBook" : bookmark.progressWithinBook,
        ]
        ] as [String : Any]
      
    if let url = NYPLConfiguration.mainFeedURL()?.appendingPathComponent("annotations/") {
        postAnnotationJSONRequest(book, url, parameters, completionHandler: { success in
          if success {
            getBookmark(book, cfi, completionHandler: { bookmark in
              completionHandler(bookmark!)
            })
          } else {
            completionHandler(nil)
          }
        })
      } else {
        Log.error(#file, "MainFeedURL does not exist")
      }
    }
  }
  
  class func deleteBookmark(annotationId:NSString) {
    guard let url: URL = URL(string: annotationId as String) else {
      Log.error(#file, "Invalid URL Created")
      return
    }
    var request = URLRequest(url: url)
    request.httpMethod = "DELETE"
    setDefaultAnnotationHeaders(forRequest: &request)
    
    let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
      if (response as? HTTPURLResponse)?.statusCode == 200 {
        Log.info(#file, "Deleted Bookmark")
      } else {
        guard let error = error as NSError? else { return }
        Log.error(#file, "Request Error Code: \(error.code). Description: \(error.localizedDescription)")
      }
    }
    task.resume()
  }

  
  private class func addToOfflineQueue(_ book: NYPLBook?, _ url: URL, _ parameters: [String:Any]) {
    let libraryID = AccountsManager.shared.currentAccount.id
    let parameterData = try? JSONSerialization.data(withJSONObject: parameters, options: [.prettyPrinted])
    NetworkQueue.addRequest(libraryID, book?.identifier, url, .POST, parameterData, headers)
  }

  class func setDefaultAnnotationHeaders(forRequest request: inout URLRequest) {
    for (headerKey, headerValue) in NYPLAnnotations.headers {
      request.setValue(headerValue, forHTTPHeaderField: headerKey)
    }
  }
  
  class var headers: [String:String] {
    if let barcode = NYPLAccount.shared().barcode, let pin = NYPLAccount.shared().pin {
      let authenticationString = "\(barcode):\(pin)"
      if let authenticationData = authenticationString.data(using: String.Encoding.ascii) {
        let authenticationValue = "Basic \(authenticationData.base64EncodedString(options: Data.Base64EncodingOptions.lineLength64Characters))"
        return ["Authorization" : "\(authenticationValue)",
                "Content-Type" : "application/json"]
      } else {
        Log.error(#file, "Error formatting auth headers.")
      }
    } else {
      Log.error(#file, "Attempted to create authorization header without a barcode or pin.")
    }
    return ["Authorization" : "",
            "Content-Type" : "application/json"]
  }
}
