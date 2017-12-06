# FindBTC

Scans devices for remnants of bitcoin wallet files. 

The tool can find wallets even if;

- The wallet was deleted, but not overwritten
- The file system is corrupted and inaccessible
- The device has been reformatted
- The wallet has been partially overwritten
- The wallet is inside a .zip or .tar.gz file, including 
  nested in multiple levels of compressed files
  
## Installing

This requires that you have the Go programming language set up on your 
machine, please see https://golang.org/doc/install 

    go install github.com/jakewins/findbtc

## Usage

    findbtc [-s start-offset] DEVICE
    
    # Eg.
    
    findbtc /dev/sda
    
## License

GPL