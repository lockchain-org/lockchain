# ZFS initrd assets (note)

The ZFS provider already ships early-boot integration for both dracut and initramfs-tools.

Today the canonical templates live under `crates/lockchain-core/templates/` because they are
rendered/installed by `lockchain-core` workflows.

This directory exists to keep the packaging tree symmetric with other providers as we evolve
boot integration packaging in later sprints.
