const deviceMac = process.env.UNIFI_DEVICE_MAC;
const device = db
  .getSiblingDB("unifi")
  .device.findOne({ mac: deviceMac }, { _id: 0, x_authkey: 1 });

if (!device || !device.x_authkey) {
  throw new Error(`No adoption key exists for ${deviceMac}`);
}

print(device.x_authkey);
