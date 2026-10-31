import Foundation
import CoreWLAN

// CoreWLAN owns regulatory channel selection. Do not select RF channels directly.
guard let name = CommandLine.arguments.dropFirst().first,
      let interface = CWWiFiClient.shared().interface(withName: name) else {
    fputs("Wi-Fi interface unavailable\n", stderr)
    exit(2)
}
do {
    do {
        // Never print scan results, addresses or credentials.
        _ = try interface.scanForNetworks(withSSID: nil)
        print("Scan completed")
    } catch {
        let code = (error as NSError).code
        fputs("Scan failed (code \(code)); stopping\n", stderr)
        exit(3)
    }
}
