import json
import sys

from ltobackup.automation import WindowsTapeDevice
from ltobackup.cli import main
from ltobackup.volume_probe import main as volume_probe_main


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--internal-volume-probe":
        raise SystemExit(volume_probe_main(sys.argv[2:]))
    if len(sys.argv) == 3 and sys.argv[1] == "--internal-tape-serial":
        device_name = sys.argv[2]
        serial_number = WindowsTapeDevice(device_name).read_unit_serial()
        print(json.dumps({"device_name": device_name, "serial_number": serial_number}))
        raise SystemExit(0)
    raise SystemExit(main())
