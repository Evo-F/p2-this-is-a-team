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

### Collaboration and Contributions

At time of most recent commit (10/25/2020), I have not collaborated with anyone for this project.

Specific code has been shamelessly borrowed from Project 1. These blocks of code have been marked as such.

