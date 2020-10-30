# Geoloc (CSCI356 Project 2)

Distributed website analyzer and geolocation service.

Contributors: Evo Fearnley (2021)

This system functions as a peer-to-peer "hive mind" network, with each node functioning simultaneously as a webserver
and worker node as needed. 

### Current Status

All code is within the file `primary.py`. This code is capable of registering and communicating with other instances
of itself at any IP address (port 9299). 

All running instances of `primary.py` have command-line access to force some very basic functionalities and inputs,
such as heartbeats and listing of known contacts.

Nodes are now capable of exchanging location data based on their cloud provider.

There are currently 8 nodes operational in the following GCP zones: US East, US Central, US West, South America East,
Europe West, Australia Southeast, Asia/Pacific East (Taiwan), Asia/Pacific Southeast (Singapore).

For best connection, access 35.245.34.243 via your web browser (that's US East).

### Collaboration and Contributions

At time of most recent commit (10/30/2020), I have not collaborated with anyone for the code on this project.

For the purposes of testing and bug identification, I enlisted the following students:
* Aidan Curtis (2021)
* Justin Bella (2021)
* Emily Mercier (2021)

These students had access to the project via the web interface **only.** None of them had access to the code.

Specific code has been shamelessly borrowed from Project 1. These blocks of code have been marked as such.

