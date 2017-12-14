import Foundation
import ZXingObjC

fileprivate let barcodeHeight: CGFloat = 100
fileprivate let maxBarcodeWidth: CGFloat = 414

@objc enum NYPLBarcodeType: Int {
  case codabar
  case code39
  case qrCode
  case code128
}

fileprivate func ZXBarcodeFormatFor(_ NYPLBarcodeType:NYPLBarcodeType) -> ZXBarcodeFormat {
  switch NYPLBarcodeType {
  case .codabar:
    return kBarcodeFormatCodabar
  case .code39:
    return kBarcodeFormatCode39
  case .qrCode:
    return kBarcodeFormatQRCode
  case .code128:
    return kBarcodeFormatCode128
  }
}

/// Manage creation and scanning of barcodes on library cards.
/// Keep any third party dependency abstracted out of the main app.
final class NYPLBarcode: NSObject {

  class func image(fromString string: String, superviewWidth: CGFloat, type: NYPLBarcodeType) -> UIImage?
  {
    let barcodeWidth = imageWidthFor(superviewWidth)
    guard let writer = ZXMultiFormatWriter.writer() as? ZXWriter else { return nilWithGenericError() }
    do {
      let encodeHints = ZXEncodeHints.init()
      encodeHints.margin = 0
      let result = try writer.encode(string,
                                     format: ZXBarcodeFormatFor(type),
                                     width: Int32(barcodeWidth),
                                     height: Int32(barcodeHeight),
                                     hints: encodeHints)
      if let cgImage = ZXImage.init(matrix: result).cgimage {
        return UIImage.init(cgImage: cgImage)
      } else {
        return nilWithGenericError()
      }
    } catch {
      Log.error(#file, "Failed to create barcode image: \(error.localizedDescription)")
      return nil
    }
  }

  class func presentScanner(withCompletion completion: @escaping (String?) -> ())
  {
    AVCaptureDevice.requestAccess(forMediaType: AVMediaTypeVideo) { granted in
      DispatchQueue.main.async {
        if granted {
          guard let scannerVC = NYPLBarcodeScanningViewController.init(completion: completion) else { return }
          let navController = UINavigationController.init(rootViewController: scannerVC)
          NYPLRootTabBarController.shared().safelyPresentViewController(navController, animated: true, completion: nil)
        } else {
          presentCameraPrivacyAlert()
        }
      }
    }
  }

  private class func presentCameraPrivacyAlert()
  {
    let alertController = NYPLAlertController(
      title: NSLocalizedString("Camera Access Disabled",
                               comment: "An alert title stating the user has disallowed the app to access the user's location"),
      message: NSLocalizedString(
        ("You must enable camera access for this application " +
          "in order to sign up for a library card."),
        comment: "An alert message informing the user that camera access is required"),
      preferredStyle: .alert)

    alertController.addAction(UIAlertAction(
      title: NSLocalizedString("Open Settings",
                               comment: "A title for a button that will open the Settings app"),
      style: .default,
      handler: {_ in
        UIApplication.shared.openURL(URL(string:UIApplicationOpenSettingsURLString)!)
    }))
    alertController.addAction(UIAlertAction(
      title: NSLocalizedString("Cancel", comment: ""),
      style: .cancel,
      handler: nil))

    alertController.present(fromViewControllerOrNil: nil, animated: true, completion: nil)
  }

  private class func imageWidthFor(_ superviewWidth: CGFloat) -> CGFloat
  {
    if superviewWidth > maxBarcodeWidth {
      return maxBarcodeWidth
    } else {
      return superviewWidth
    }
  }

  private class func nilWithGenericError() -> UIImage?
  {
    Log.error(#file, "Error creating image from barcode string.")
    return nil
  }
}
