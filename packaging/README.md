# Distribution kit

Everything in this folder exists so scouter26 can be installed without
compiling on as many distros as possible.

## What's here

| File | Purpose |
| ---- | ------- |
| `PKGBUILD` | Arch-family package (`scouter26-bin`), built from the official release tarball |

The Debian `.deb` and Fedora `.rpm` are generated automatically by
[.github/workflows/release.yml](../.github/workflows/release.yml) on every
version tag — their recipe lives in `Cargo.toml` under
`package.metadata.deb` and `package.metadata.generate-rpm`.

## Testing the Arch package locally (on an Arch box)

```bash
cd packaging
updpkgsums          # fill in real checksums for the current pkgver
makepkg -si         # builds and installs scouter26-bin
scouter26 --version
```

## Publishing to the AUR (one-time setup)

1. Create an account at <https://aur.archlinux.org> and add an SSH key.
2. Clone the (empty) package base: `git clone ssh://aur@aur.archlinux.org/scouter26-bin.git`
3. Copy `PKGBUILD` in, generate the metadata: `makepkg --printsrcinfo > .SRCINFO`
4. `git add PKGBUILD .SRCINFO && git commit -m "scouter26-bin 0.10.0" && git push`

After every release: bump `pkgver`, run `updpkgsums`, regenerate `.SRCINFO`,
push. AUR users then get `yay -S scouter26-bin`.

## The official-repositories milestone (future)

Getting scouter26 into Debian, Fedora's official repos, or the AUR *as a
maintained package* means going through each distro's review process
(Debian Mentors, a Fedora sponsor, AUR co-maintainership). This kit is the
practical equivalent today: same file formats, installable directly from
GitHub Releases.

## Why there is no Flatpak here (on purpose)

Flatpak sandboxes *desktop GUI applications*; a terminal tool packaged
that way cannot be run as plain `scouter26` in a shell (it would be
`flatpak run com.lab026.scouter26`), Flathub is almost exclusively GUI
software, and a network scanner actually *loses* usefulness inside a
network sandbox. If scouter26 ever grows a graphical interface, a Flatpak
manifest becomes the right tool for that job — and this kit will be the
first to know.
