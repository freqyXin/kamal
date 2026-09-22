# Encrypted zram Writeback Activation Runbook

## Status

This feature is prepared but **not active**.

Do not perform the first production activation or reboot during a remote-only
maintenance window. Physical console access or equivalent out-of-band recovery
must be available.

## Validated

The following have been validated on the target Raspberry Pi:

- cryptsetup 2.7.5 plain dm-crypt operation
- `/dev/urandom` as fresh random key material
- AES-XTS with a 512-bit key
- plaintext written through dm-crypt is not visible in the backing file
- disposable dm-crypt mapping creation and cleanup
- systemd 257 crypttab generation
- `noauto` behavior
- generated mapper-device dependency
- zram-generator configuration precedence
- repository dependency relationships
- repository static validation
- existing zram and swap remained unaffected during testing

## Not yet validated

The following require a controlled production integration test:

- first boot with encrypted writeback
- failure when the encrypted mapping cannot be created
- unexpected mapper loss while zram is active
- effective shutdown ordering
- rollback after a deliberately induced failure

## Security goal

Protect zram writeback pages stored in `/var/swap` from being persisted as
plaintext on the NVMe device.

The intended device chain is:

```text
/var/swap
    |
    v
rpi-setup-loop@var-swap.service
    |
    v
/dev/disk/by-backingfile/var-swap
    |
    v
systemd-cryptsetup@kamal\x2dswap.service
    |
    v
/dev/mapper/kamal-swap
    |
    v
systemd-zram-setup@zram0.service
    |
    v
/dev/zram0
```

The dm-crypt key is generated from `/dev/urandom` whenever the plain-mode
mapping is created. The key is not persisted.

The existing `rpi-zram-writeback.timer` remains enabled.

## Security limitations

This does not provide full-disk encryption.

It does not protect plaintext written elsewhere on the root filesystem,
including logs, temporary files, application storage, or other unencrypted
locations.

Historical plaintext previously written to `/var/swap` may remain recoverable
from the SSD because of filesystem allocation, flash translation, garbage
collection, wear leveling, or remapped NAND blocks.

Deleting or overwriting `/var/swap` must not be described as cryptographic
erasure of historical data.

## Repository components

```text
deploy/crypttab/kamal-swap.conf

deploy/systemd/
  systemd-cryptsetup@kamal\x2dswap.service.d/
    90-kamal-loop-ordering.conf

deploy/systemd/
  systemd-zram-setup@zram0.service.d/
    90-kamal-encrypted-writeback.conf

deploy/zram/
  90-kamal-encrypted-writeback.conf
```

These components are intended to be installed together.

## Crypttab entry

```text
kamal-swap /dev/disk/by-backingfile/var-swap /dev/urandom plain,cipher=aes-xts-plain64,size=512,noauto
```

Important properties:

- `plain` selects plain dm-crypt.
- `cipher=aes-xts-plain64` selects AES-XTS.
- `size=512` selects the XTS key size in bits.
- `/dev/urandom` supplies random key material.
- `noauto` prevents `cryptsetup.target` from automatically pulling the mapping in.
- The `swap` crypttab option is deliberately absent.

Do not add the `swap` option. The encrypted mapping is backing storage for
zram; it must not itself be formatted with `mkswap`.

## Expected pre-activation state

Before installation:

```text
/dev/zram0                    active swap
/sys/block/zram0/backing_dev  /dev/loop0
/dev/mapper/kamal-swap        absent
```

Verify with:

```bash
swapon --show
cat /sys/block/zram0/backing_dev
test ! -e /dev/mapper/kamal-swap
```

## Activation prerequisites

Do not proceed unless:

- physical or out-of-band recovery is available
- current repository changes are committed
- important evidence is backed up
- `/dev/zram0` is operating normally
- `/dev/loop0` is its current writeback device
- `/dev/mapper/kamal-swap` is absent
- sufficient maintenance time exists for rollback
- runtime fail-closed behavior is understood to remain unvalidated

Record:

```bash
date
uname -a
systemctl --version
cryptsetup --version
swapon --show
cat /sys/block/zram0/backing_dev
```

## Installation

### Create drop-in directories

```bash
sudo install -d -m 0755 \
  '/etc/systemd/system/systemd-cryptsetup@kamal\x2dswap.service.d' \
  '/etc/systemd/system/systemd-zram-setup@zram0.service.d' \
  /etc/systemd/zram-generator.conf.d
```

### Install cryptsetup ordering

From the repository root:

```bash
sudo install -m 0644 \
  'deploy/systemd/systemd-cryptsetup@kamal\x2dswap.service.d/90-kamal-loop-ordering.conf' \
  '/etc/systemd/system/systemd-cryptsetup@kamal\x2dswap.service.d/90-kamal-loop-ordering.conf'
```

### Install zram ordering

```bash
sudo install -m 0644 \
  'deploy/systemd/systemd-zram-setup@zram0.service.d/90-kamal-encrypted-writeback.conf' \
  '/etc/systemd/system/systemd-zram-setup@zram0.service.d/90-kamal-encrypted-writeback.conf'
```

### Install zram writeback override

```bash
sudo install -m 0644 \
  deploy/zram/90-kamal-encrypted-writeback.conf \
  /etc/systemd/zram-generator.conf.d/90-kamal-encrypted-writeback.conf
```

The `90-` file overrides the Raspberry Pi-generated `20-` value only for
`writeback-device`, while retaining the existing zram size and other settings.

### Install crypttab entry

First inspect:

```bash
grep -nE '^[[:space:]]*kamal-swap[[:space:]]' /etc/crypttab || true
```

There must not already be an active `kamal-swap` entry.

Then append the repository entry:

```bash
grep -vE '^[[:space:]]*(#|$)' deploy/crypttab/kamal-swap.conf |
  sudo tee -a /etc/crypttab >/dev/null
```

Verify exactly one active entry exists:

```bash
grep -nE '^[[:space:]]*kamal-swap[[:space:]]' /etc/crypttab
```

Reload systemd metadata:

```bash
sudo systemctl daemon-reload
```

Do not manually restart the active zram, swap, or loop services during the
first deployment.

The first activation should occur through a controlled reboot.

## First activation

Only perform the first reboot when physical recovery is available.

Immediately before reboot:

```bash
swapon --show
cat /sys/block/zram0/backing_dev
test ! -e /dev/mapper/kamal-swap &&
  echo 'PASS: mapper absent before first activation'
```

Then use the normal administrative reboot procedure.

## Post-boot acceptance criteria

### Encrypted mapping exists

```bash
sudo cryptsetup status kamal-swap
```

Expected properties include:

```text
type:    PLAIN
cipher:  aes-xts-plain64
keysize: 512 bits
```

### zram uses encrypted backing

```bash
cat /sys/block/zram0/backing_dev
readlink -f /dev/mapper/kamal-swap
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS
```

The zram backing device must resolve to the dm-crypt mapping, not `/dev/loop0`.

### Swap remains active

```bash
swapon --show
```

`/dev/zram0` must remain active.

### Services are healthy

```bash
systemctl --failed --no-pager

systemctl status \
  'rpi-setup-loop@var-swap.service' \
  'systemd-cryptsetup@kamal\x2dswap.service' \
  'systemd-zram-setup@zram0.service' \
  'dev-zram0.swap' \
  'rpi-zram-writeback.timer' \
  --no-pager
```

### Writeback timer remains operational

```bash
systemctl is-enabled rpi-zram-writeback.timer
systemctl is-active rpi-zram-writeback.timer
systemctl list-timers rpi-zram-writeback.timer --no-pager
```

## Fail-closed test

A controlled future test must demonstrate that if
`systemd-cryptsetup@kamal\x2dswap.service` cannot create the mapper:

- zram does not silently revert to `/dev/loop0`
- plaintext writeback does not occur
- the failure is visible in systemd state and logs
- boot and network recovery behavior are understood

Until that test succeeds, fail-closed runtime behavior remains unvalidated.

## Shutdown test

A controlled future test must confirm that zram stops before dm-crypt and that
dm-crypt stops before its backing loop device.

The expected conceptual stop order is:

```text
dev-zram0.swap
    |
    v
systemd-zram-setup@zram0.service
    |
    v
systemd-cryptsetup@kamal\x2dswap.service
    |
    v
rpi-setup-loop@var-swap.service
```

The loop device must never be detached while the dm-crypt mapping still
depends on it.

## Rollback

Perform rollback from a local or otherwise reliable recovery session.

Remove the K'amal zram override:

```bash
sudo rm -f \
  /etc/systemd/zram-generator.conf.d/90-kamal-encrypted-writeback.conf
```

Remove the K'amal systemd drop-ins:

```bash
sudo rm -f \
  '/etc/systemd/system/systemd-cryptsetup@kamal\x2dswap.service.d/90-kamal-loop-ordering.conf' \
  '/etc/systemd/system/systemd-zram-setup@zram0.service.d/90-kamal-encrypted-writeback.conf'
```

Back up crypttab:

```bash
sudo cp -a /etc/crypttab /etc/crypttab.kamal-rollback
```

Remove only the active entry whose first field is exactly `kamal-swap`:

```bash
sudo awk '
  /^[[:space:]]*#/ { print; next }
  NF == 0 { print; next }
  $1 == "kamal-swap" { next }
  { print }
' /etc/crypttab |
  sudo tee /etc/crypttab.kamal-new >/dev/null

sudo install -m 0644 \
  /etc/crypttab.kamal-new \
  /etc/crypttab

sudo rm -f /etc/crypttab.kamal-new
```

Verify it is absent:

```bash
grep -nE '^[[:space:]]*kamal-swap[[:space:]]' /etc/crypttab || true
```

Reload metadata:

```bash
sudo systemctl daemon-reload
```

Do not manually tear down an in-use encrypted zram backing chain.

Use a controlled reboot.

After rollback and reboot:

```bash
swapon --show
cat /sys/block/zram0/backing_dev
test ! -e /dev/mapper/kamal-swap &&
  echo 'PASS: K amal mapper absent'
```

Expected original state:

```text
/dev/zram0                    active
/sys/block/zram0/backing_dev  /dev/loop0
/dev/mapper/kamal-swap        absent
```

## Recovery from failed first boot

If the first activation prevents normal boot:

1. use physical console or equivalent out-of-band recovery
2. remove the zram-generator override
3. remove both K'amal systemd drop-ins
4. remove only the `kamal-swap` crypttab entry
5. reload systemd if operating in normal userspace
6. reboot
7. verify zram again uses `/dev/loop0`

Do not delete `/var/swap` merely as part of boot recovery.

## Production validation complete only when

All of these have been demonstrated:

- automatic encrypted mapping creation at boot
- zram writeback uses the encrypted mapper
- `/dev/zram0` functions normally
- periodic writeback functions normally
- cryptsetup failure is fail-closed
- unexpected mapper-loss behavior is understood
- shutdown completes cleanly
- reboot completes cleanly
- rollback restores `/dev/loop0`
- normal successful boot requires no manual intervention
