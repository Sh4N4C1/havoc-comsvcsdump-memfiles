# havoc-comsvcsdump-memfiles


<p align="center">
<img src="https://raw.githubusercontent.com/Sh4N4C1/gitbook/main/images/comsvcsdump_memfiles.png" alt="comsvcsdump_memfiles">
</p>

All work by the talented [Octoberfest7](https://github.com/Octoberfest7)

This project is basically based on [memFiles](https://github.com/Octoberfest7/memFiles)

Details are all at [memFiles](https://github.com/Octoberfest7/memFiles), I'm just trying to port to Havoc c&c.

I deleted unnecessary hooks for MiniWriteDump, such as NtFlushBuffersFile.Please note that you must have a high level administrator token (UAC bypass).You can find the .dmp file in havoc’s loot

## Install

```bash
git clone https://github.com/Octoberfest7/memFiles
make
# and then load python script into Havoc C&C
```

## Usage

```bash
comsvcsdump_memfiles
```

## Process

- Install NtAPi Hook via [Memfile][https://github.com/Octoberfest7/memFiles]
- Call MiniWriteDump 
- Fetch Memfiles
- Clean Memfiles
