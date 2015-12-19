# ssh

Remote CURL is an application that can make curl requests behind a jump box by establishing an SSH connection to the jump box, and then curling a route inside the jump box's network.
This is intended to be used within the confines of a VPC/VPN situation.

GTN, or GoTunnel, is an application that establishes an SSH connection to a remote machine, and then establishes a connection to a remote host over a specified host:port and proxies information as if the remote service, such as MySQL, is running on the user's local machine.

Currently, in order to make this compile, you need to fix import paths. I wrote this on my own time at SessionM and have been using it there, so currently it is still part of SessionM's shared library.
