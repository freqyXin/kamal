# Offline Bluetooth identifier registries

K'amal resolves Bluetooth company identifiers, standard 16-bit service
UUIDs, and member-assigned 16-bit UUIDs using locally generated JSON files.

The generated registries are excluded from Git. Generate them locally
from the Bluetooth SIG Assigned Numbers repository.

## Setup

Clone the source at the revision used for K'amal v0.5.0:

    git clone https://bitbucket.org/bluetooth-SIG/public.git /tmp/bluetooth-sig-public
    git -C /tmp/bluetooth-sig-public checkout 4904c3c7317045c40513890645e7d5910bf46308

Create an isolated Python environment:

    python3 -m venv /tmp/kamal-registry-venv
    /tmp/kamal-registry-venv/bin/python -m pip install PyYAML

From the K'amal repository root, generate the registries:

    /tmp/kamal-registry-venv/bin/python tools/import_bluetooth_sig.py

This generates:

- data/bluetooth/company_identifiers.json
- data/bluetooth/service_uuids.json
- data/bluetooth/member_uuids.json

The scanner reads these JSON files offline. PyYAML is only required
during registry generation, not during scanning.

## Interpretation

Assigned company identifiers do not confirm the physical manufacturer
of a device.

Advertised UUIDs do not establish that GATT services were enumerated.

Unknown identifiers mean they were not found in the applicable local
registry snapshot.
