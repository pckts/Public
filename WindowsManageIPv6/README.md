# Windows-ManageIPv6

This contains the full functionality of the legacy version:
https://github.com/pckts/Archive/Windows-DisableIPv6

additionally it is also able to clean up and restore pre-deployment functionality post-deployment


#--------------

To do:
1. verify that WMI filter is actually applied
2. make successful exit codes as pretty as errors
4. somehow incoorporate version control and auto-updates? have a vN (v1, v2, etc) file in repo and corresponding in deployment, have scheduled task that checks once daily if these 2 matches, if not automatically performs redeployment without interferring with _reports folder?
