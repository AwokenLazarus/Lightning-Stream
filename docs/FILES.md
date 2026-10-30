# Files: a shared folder, sold per GB

A seller can share a folder on their box with no media server: films, music, books, anything. Buyers see
each file's name, size and price, and either **download** it or **open it in their own player** (VLC,
mpv, a TV app). Either way they pay as it arrives, a little at a time, within their spending rules, and
stop paying when it stops. Nobody makes an account.

For a Netflix-like experience (posters, accounts, where you stopped, 4K that adapts to the network),
share Jellyfin or Plex as a web app instead ([SELLER-APPS.md](SELLER-APPS.md)). Lightning Stream has
no player of its own.

## Selling

On the Sell page, add a service and pick **Files**. There is no address to type: the app serves the
folder itself. Price it per GB (the suggested price is 1,000 sat a GB). Put files in the folder, then
press **Update the file list**, or save the service again. The listing names each file with its size,
read from the folder at that moment. Hidden files (names starting with a dot) and anything that is not
a regular file are left out, and so is a link that leads out of the folder. At most 400 files are
listed, four folders deep.

| Platform | The folder |
|---|---|
| Linux | `XBT_UI_FILES_DIR`, by default `<the UI's data dir>/files`: point it at any folder |
| Umbrel | a folder the owner chooses on the Sell page, under the **Downloads** folder of Umbrel's Files app |
| StartOS | `<the UI's data dir>/files` in the package's volume |

**Umbrel.** The app mounts Umbrel's shared Downloads **read-only** (`/downloads` in the app; the
`STORAGE_DOWNLOADS` permission), as media apps on Umbrel do. The owner puts files in Downloads with
Umbrel's Files app, then picks the folder to share under **Which folder** on the Sell page: all of
Downloads, or one folder in it. Stream only reads it and never changes or deletes a file. The choice
is kept in `<the UI's data dir>/files-folder` and read for every request, so a new choice applies at
once. A choice is held to Downloads as the files are: no `..`, no hidden names, no link that leads out
of it; a choice that leads out (written by hand, say) shares nothing at all.

Any Linux box can do the same: set `XBT_UI_FILES_ROOT` to a folder (mounted read-only if you like) and
`XBT_UI_FILES_ROOT_WORDS` to what the page should call it; the owner then chooses under it.

**StartOS** has no shared folder of the box's files that a package can read, so the folder stays in
the package's own volume, reached with StartOS's file tools.

### How it is served

The wallet app serves the folder on its own address (`XBT_UI_FILES_BIND`, `127.0.0.1:8486` by default).
Only the shop's gateway is its client (`XBT_UI_FILES_UPSTREAM`, as the gateway's container reaches it).
Every request needs the files key, which the app keeps in its secrets and the gateway's route adds, so
another program on the box's network gets nothing for free. The route answers `GET` and `HEAD` only.
The folder serves one plain byte range at a time (`206`, `Accept-Ranges: bytes`), so a player that seeks
pays only for what it reads.

## Buying

A Files service shows under **Files** on Browse. Its page lists each file:

- **Download**: from the app's own address, so a browser on another device of the network can use it
  too. The connector pays the seller as the file arrives, and stops when the download stops.
- **Open in your player**: makes a link (`<app address>/r/<token>`) to paste into VLC (Media, Open
  Network Stream), run as `mpv '<link>'`, or add in a TV app. The link plays that one file, seeking
  included, from any device that reaches the app, without a login. It stops when it expires
  (`XBT_UI_RELAY_LINK_S`, 6 hours by default) or the owner revokes it. A restart of the app revokes
  every link.

A ranged read (a player seeking) is asked for in parts of at most 4 MiB, so a player that stops is
charged at most one part beyond what it received.

An older media listing that names films (from a seller before this change) is shown the same way: its
films can be downloaded or opened in a player.
