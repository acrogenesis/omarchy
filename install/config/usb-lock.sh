# Installed root files, with no dependency on the build machine's devices.
install -Dm644 "$OMARCHY_PATH/default/polkit/org.omarchy.usb-lock.policy" /usr/share/polkit-1/actions/org.omarchy.usb-lock.policy
/usr/bin/omarchy-usb-lock-admin install
