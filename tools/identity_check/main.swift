import AppKit
import CoreLocation
import CoreWLAN

final class IdentityCheck: NSObject, NSApplicationDelegate, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    private var window: NSWindow!
    private let result = NSTextField(wrappingLabelWithString: "")
    func applicationDidFinishLaunching(_ notification: Notification) {
        manager.delegate = self
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 570, height: 340), styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "AirportRTW Identity Check"
        let view = NSView(frame: window.contentView!.bounds)
        let info = NSTextField(wrappingLabelWithString: "macOS requires Location permission to read Wi-Fi identity. This app reads the current SSID, BSSID and country through CoreWLAN. It does not request coordinates, scan, change networks, or upload information.")
        info.frame = NSRect(x: 22, y: 235, width: 526, height: 80)
        view.addSubview(info)
        let authorize = NSButton(title: "Allow Location Access…", target: self, action: #selector(allow))
        authorize.frame = NSRect(x: 20, y: 190, width: 220, height: 32)
        view.addSubview(authorize)
        let refresh = NSButton(title: "Refresh", target: self, action: #selector(readIdentity))
        refresh.frame = NSRect(x: 250, y: 190, width: 110, height: 32)
        view.addSubview(refresh)
        result.frame = NSRect(x: 22, y: 20, width: 526, height: 155)
        result.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        result.isSelectable = true
        view.addSubview(result)
        window.contentView = view
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        readIdentity()
    }
    @objc private func allow() {
        guard CLLocationManager.locationServicesEnabled() else {
            result.stringValue = "Location Services is disabled. Enable it in System Settings → Privacy & Security → Location Services, then retry."
            return
        }
        manager.requestWhenInUseAuthorization()
        readIdentity()
    }
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) { readIdentity() }
    @objc private func readIdentity() {
        // The delegate can be notified before the app has finished launching.
        guard window != nil else { return }
        let status = manager.authorizationStatus
        guard status == .authorizedAlways else {
            result.stringValue = "Location authorization: \(status.rawValue)\n\nClick Allow Location Access, then accept the macOS prompt.\nIf access was denied, enable this app in Location Services.\nNo Wi-Fi identity has been requested by this app yet."
            return
        }
        guard let iface = CWWiFiClient.shared().interface() else {
            result.stringValue = "Location authorized. CoreWLAN returned no default Wi-Fi interface."
            return
        }
        let ssid = iface.ssid() ?? "Unavailable"
        let bssid = iface.bssid() ?? "Unavailable"
        let country = iface.countryCode() ?? "Unavailable"
        result.stringValue = "Location authorization: granted\nInterface: \(iface.interfaceName ?? "Unknown")\nSSID: \(ssid)\nBSSID: \(bssid)\nCountry: \(country)\n\nUnavailable values still require investigation. Country 00 does not establish a geographic domain."
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
let application = NSApplication.shared
let delegate = IdentityCheck()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()
