<img src='https://github.com/microsoft/routeros-scanner/blob/main/assets/img/section52.png' img align='right' width='377' height='100'/>
<br/>

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

This tool requires Python 3.8 or later. 

### Install required Python packages
`pip install -r requirements.txt`
	
### The arguments:
 **args**  | **Description**							                                      | **Must / Optional**
-----------| ------------------------------------------------------------------------------| -------------------
`-i`	   | The tested Mikrotik IP address			                                       | Must
`-p`	   | The tested Mikrotik SSH port			                                       | Optional
`-u`	   | User name with admin Permissions		                                       | Must
`-ps`      | The password of the given user name	(empty password by default)	           | Optional
`-J`	   | Print the results as json format (prints txt format by default)	           | Optional
`-concise` | Print a shortened text output focusing on recommendations and suspicious data | Optional
`-update`  | Update the CVE Json file (the file is updated automatically if it hasn't been updated in the last month)| Optional

### Executing examples:
	 ./main.py -i 192.168.88.1 -u admin
	 ./main.py -i 192.168.88.1 -p 22 -u admin
	 ./main.py -i 192.168.88.1 -p 2000 -u admin -ps 123456
	 ./main.py -i 192.168.88.1 -p 2000 -u admin -ps 123456 -J

### Output:
The output includes 3 sections for each test:
1. raw data - all the data we search in.
2. suspicious - things we found out as suspicious - should be checked if they are legitimate or malicious.
3. recommendation - things we found out as weak security points and recommendations for fixing them.

## More info & solution:
Researchers developed this forensic tool while investigating how MikroTik devices are used in Trickbot C2 infrastructure. 
You can read more about the research [here](https://www.microsoft.com/security/blog/2022/03/16/uncovering-trickbots-use-of-iot-devices-in-command-and-control-infrastructure/).

[Microsoft Defender for IoT](https://azure.microsoft.com/en-us/services/iot-defender/#overview) is an agentless network-layer security solution that allows 
organizations to continuously monitor and discover assets, detect threats, and manage vulnerabilities in their IoT/OT 
and Industrial Control Systems (ICS) devices, on-premises and in Azure-connected environments.

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

## Legal Disclaimer

Copyright (c) 2018 Microsoft Corporation. All rights reserved.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
