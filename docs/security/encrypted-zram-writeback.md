# Encrypted zram writeback

Status: design and preparation only. Not installed.

## Existing system

Raspberry Pi OS rpi-swap 1.2.4 manages zram0 and a loop-backed
writeback file at /var/swap.

The generated zram configuration currently selects:

    /dev/disk/by-backingfile/var-swap

The existing backing file is on the unencrypted NVMe root filesystem.

## Intended design

    zram0
      |
      v
    /dev/mapper/kamal-swap
      |
      v
    /dev/disk/by-backingfile/var-swap
      |
      v
    /var/swap on NVMe

The dm-crypt mapping must use a fresh random key on every boot.
The key must not be written to persistent storage.

## Required safeguards

1. Preserve Raspberry Pi OS's existing swap-file and loop setup.
2. Open the encrypted mapping only after loop setup completes.
3. Initialize zram only after the encrypted mapping is available.
4. Never fall back to the unencrypted loop device.
5. Do not close the mapping while zram is using it.
6. Permit the operating system and networking to boot if swap
   initialization fails.
7. Validate reboot behavior with physical recovery available.
8. Provide a tested rollback procedure before activation.

## Activation prerequisites

- Implement and review the dm-crypt setup service.
- Verify systemd startup and shutdown ordering.
- Validate the effective zram-generator configuration.
- Test encryption setup and failure handling.
- Establish physical recovery and rollback procedures.

Do not activate the zram override until all prerequisites pass.

## Residual risks

This change protects future writeback, not historical plaintext
already written to /var/swap.

It does not encrypt the operating system, logs, temporary files,
existing evidence, or the evidence volume itself.

A powered-on device may retain encryption keys in memory.

## Package-managed implementation

Installed packages:
- cryptsetup 2.7.5
- cryptsetup-bin 2.7.5
- systemd-cryptsetup 257.13

Candidate configuration:
- deploy/crypttab/kamal-swap.conf
- deploy/zram/90-kamal-encrypted-writeback.conf

The crypttab entry is not installed or active.

The mapping uses plain dm-crypt with a fresh random key at each
activation. It is disposable storage and cannot be reopened after
the mapping is closed.

Do not use the crypttab swap option: zram requires a raw backing
block device, not a separately formatted swap device.

Before activation, validate:
- systemd's interpretation of hash=plain and /dev/urandom;
- the generated cryptsetup unit and its loop-device dependencies;
- zram's dependency on successful mapping activation;
- shutdown ordering;
- behavior when encryption setup fails;
- rollback and physical recovery.
