# drivecom - Phison USB flasher and utilities

This is a Python v3.x script to communicate with Phison USB flash drive controllers. It allows retrieving drive information, flashing firmware, executing RAM, jumping to boot mode, as well as file operations such as splitting firmware images into separate page files.

For Windows, use the drive letter as the device path.
For Linux, use /dev/sg* as the device path. (You'll have to figure out yourself which /dev/sg* device to use.)
For OS X, you will need to unload the USB mass storage driver and install a libusb driver and use this script with libusb. This method also works for Windows and Linux, but is more painful to use.

For more help in using it, run "drivecom -h" or view the code.
