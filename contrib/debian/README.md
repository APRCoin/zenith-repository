
Debian
====================
This directory contains files used to package aprcoind/aprcoin-qt
for Debian-based Linux systems. If you compile aprcoind/aprcoin-qt yourself, there are some useful files here.

## aprcoin: URI support ##


aprcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install aprcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your aprcoinqt binary to `/usr/bin`
and the `../../share/pixmaps/aprcoin128.png` to `/usr/share/pixmaps`

aprcoin-qt.protocol (KDE)

