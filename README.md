# SPIblock
SPIblock is a proof of concept tool that allows programming on-flash write protection. It supports most common SPI flash chips, which are identified using [flashrom](https://github.com/flashrom/flashrom)'s database.

## Requirements
SPIblock requires:

- Python 3.2 or higher
- [pyBusPirateLite](https://github.com/juhasch/pyBusPirateLite) library
- Bus Pirate v3.6 or v4

## Usage
    usage: spiblock.py [-h] [-u USPEED] [-x SPEED] [-d DEV] [-t TIMEOUT] [-v] [-f]
                   [-p] [-s] [-b BP] [-w WP] [--version]

	SPIblock
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -u USPEED, --uspeed USPEED
	                        Set UART speed
	  -x SPEED, --speed SPEED
	                        Set SPI speed
	  -d DEV, --dev DEV     Set Bus Pirate device path
	  -t TIMEOUT, --timeout TIMEOUT
	                        Set SPI timeout in seconds
	  -v, --verbose         Enable verbose output
	  -f, --force           Assume SPI device supports generic write protection
	  -p, --probe           Probe for SPI device
	  -s, --status          Get SPI device status
	  -b BP, --bp-state BP  Enable (1) or disable (0) block protection
	  -w WP, --wp-state WP  Enable (1) or disable (0) WP pin control
	  --version             show program's version number and exit
	  
## License
See the [LICENSE](LICENSE) file.