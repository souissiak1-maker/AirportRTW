# AirportRTW

macOS Wi-Fi driver for supported Realtek RTW88 and RTW89 PCIe cards. One kext contains both HALs and selects the backend automatically by PCI ID.

## Compatibility

Build targets cover macOS High Sierra (10.13) through Sonoma (14), plus an experimental native Wi-Fi frontend for Sequoia 15.2+ and Tahoe 26.x on x86_64.

Supported cards:

RTW88:
RTL8723DE, RTL8812AE, RTL8814AE, RTL8821AE, RTL8821CE, RTL8822BE, RTL8822CE

RTW89:
RTL8851BE, RTL8852AE, RTL8852BE, RTL8852CE, and RTL8922AE

## How to Use

1- Copy AirportRTW.kext to EFI/OC/Kexts.

2- In OpenCore Kernel -> Add, load the kexts in this order: Lilu, AMFIPass, AirportRTW.

3- Set Misc -> Security -> SecureBootModel to Disabled.

4- Reboot and enjoy.

## Credits

Special thanks to the [OpenIntelWireless/itlwm](https://github.com/OpenIntelWireless/itlwm) project. Its modular architecture provided the foundation we adapted to connect the Realtek backend to AirportRTW, making support for Realtek Wi-Fi cards possible.
