[comment]: # "Auto-generated SOAR connector documentation"
# McAfee OpenDXL

Publisher: Martin Ohl  
Connector Version: 1\.1\.2  
Product Vendor: McAfee  
Product Name: OpenDXL  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.251  

Push Notfications over McAfee OpenDXL


## Certificate Creation

Please follow the McAfee OpenDXL Python Client SDK Documentation
<https://opendxl.github.io/opendxl-client-python/pydoc/certcreation.html>

## Update the OpenDXL Libraries if Necessary

Please follow:

-   <https://github.com/opendxl/opendxl-client-python>
-   <https://github.com/opendxl/opendxl-tie-client-python>
-   <https://github.com/opendxl/opendxl-mar-client-python>


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a OpenDXL asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**dxl\_topic** |  optional  | string | DXL Topic
**dxl\_tmsg** |  optional  | string | OpenDXL Test Message

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for DXL connectivity\.  
[post ip](#action-post-ip) - Push an event over the McAfee DXL fabric  
[post hash](#action-post-hash) - Push a MD5 Hash into the TIE Database  
[lookup hash](#action-lookup-hash) - Lookup MD5 Hash with McAfee Active Response  

## action: 'test connectivity'
Validate the asset configuration for DXL connectivity\.

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'post ip'
Push an event over the McAfee DXL fabric

Type: **contain**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**dxl\_ip** |  required  | DXL message to push | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.dxl\_ip | string |  `ip`   

## action: 'post hash'
Push a MD5 Hash into the TIE Database

Type: **contain**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**tie\_md5** |  required  | Hash to push into TIE | string |  `md5` 
**dxl\_rep** |  required  | TIE Reputation | string |  `dxl reputation` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.dxl\_rep | string |  `dxl reputation` 
action\_result\.parameter\.tie\_md5 | string |  `md5`   

## action: 'lookup hash'
Lookup MD5 Hash with McAfee Active Response

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**mar\_md5** |  required  | MD5 Lookup with MAR | string |  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.items\.\*\.id | string | 
action\_result\.data\.\*\.items\.\*\.count | numeric | 
action\_result\.data\.\*\.items\.\*\.output\.Files\|md5 | string |  `md5` 
action\_result\.data\.\*\.items\.\*\.output\.Files\|status | string | 
action\_result\.data\.\*\.items\.\*\.output\.HostInfo\|hostname | string |  `host name` 
action\_result\.data\.\*\.items\.\*\.output\.HostInfo\|ip\_address | string |  `ip` 
action\_result\.data\.\*\.items\.\*\.created\_at | string | 
action\_result\.data\.\*\.startIndex | numeric | 
action\_result\.data\.\*\.totalItems | numeric | 
action\_result\.data\.\*\.itemsPerPage | numeric | 
action\_result\.data\.\*\.currentItemCount | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.parameter\.mar\_md5 | string |  `md5` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 