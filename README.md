# remarkapy

> [!WARNING]
> This repository is currently under construction and cannot be used. ETA late autumn 2024.

A Python package for interacting with the Remarkable Cloud API.

Specifically targeting _my personal needs_ for projects such as

* [@j6k4m8/Goosepaper](https://github.com/j6k4m8/Goosepaper) — daily newspaper / RSS or feed syndicator that generates a document for the reMarkable
* [@j6k4m8/remarkabib](https://github.com/j6k4m8/remarkabib) — reference and bibliography management with the reMarkable
* [@j6k4m8/epistolary](https://github.com/j6k4m8/epistolary) — an email client that lets you hand-write replies on the reMarkable

But if you have use-cases, let's support them!


## Why another

As far as I can tell, all the major players in the reMarkable client SDK space are pretty much defunct.

* [@subutux/rmapy](https://github.com/subutux/rmapy) is archived because of the moving target of the reMarkable API.
* [@splitbrain/reMarkableAPI](https://github.com/splitbrain/ReMarkableAPI) no longer appears to work.
* [@juruen/rmapi](https://github.com/juruen/rmapi), which was the de facto standard for a while, is also archived as of July 2024.

This sucks. reMarkable seems to be deliberately avoiding all of the excited developer momentum behind these projects and is instead making fiddly tweaks that break compatibility every few months. It bums me out.

This is my attempt to make a simple, easy-to-use Python package for interacting with the reMarkable Cloud API. Contributions are VERY welcome.

## Roadmap

- [ ] Base authentication
- [ ] List documents
- [ ] Download documents by ID
- [ ] Download PDFs of documents with annotations included
- [ ] Upload documents (PDFs, EPUBs, etc.)
- [ ] Delete documents by ID
- [ ] Create folders
- [ ] List folders
- [ ] Delete folders by ID
- [ ] Move documents between folders
- [ ] Rename documents
- [ ] Rename folders
- [ ] Syncing to a local directory
- [ ] Syncing from a local directory
- [ ] Device registration from a short code
