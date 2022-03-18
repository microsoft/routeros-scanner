# RouterOS Scanner

Forensics tool for Mikrotik devices. Search for suspicious properties and weak security points that need to be fixed on the router.

This tool’s functionalities include the following: 
- Get the version of the device and map it to CVEs 
- Check for scheduled tasks 
- Look for traffic redirection rules 
- Look for DNS cache poisoning 
- Look for default ports change 
- Look for non-default users 
- Look for suspicious files
- Look for proxy, socks and FW rules

## Executing and arguments
	
### The arguments:

 **args** | **Description**							                        | **Must / Optional**
----------| ----------------------------------------------------------------| -------------------
`-i`	  | The tested Mikrotik IP address			                        | Must
`-p`	  | The tested Mikrotik SSH port			                        | Must
`-u`	  | User name with admin Permissions		                        | Must
`-ps`     | The password of the given user name	(empty password by default)	| Optional
`-J`	  | Print the results as json format (prints txt format by default)	| Optional

### Executing examples:
	 ./main.py -i 1.2.3.4 -p 22 -u admin
	 ./main.py -i 1.2.3.4 -p 2000 -u admin -ps 123456
	 ./main.py -i 1.2.3.4 -p 2000 -u admin -ps 123456 -J

### Output:
The output includes 3 sections for each test:
1. raw data - all the data we search in.
2. suspicious - things we found out as suspicious and recommends checking if they are legitimate or malicious.
3. recommendation - things we found out as weak security points and recommends to fix.


## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
