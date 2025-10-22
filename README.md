# IG-EXTCAP

Wireshark extcap provider for connecting to the [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget)
[tcpdump gadget](https://inspektor-gadget.io/docs/latest/gadgets/tcpdump).

This requires a running installation of Inspektor Gadget either as Kubernetes Daemonset or in daemon mode (using
`ig daemon`).

## Installation

Start Wireshark and go to its "About" dialog. Under the "folders" tab look for "Personal Extcap path" and copy the
ig-extcap binary file for your specific platform there.

## Usage

After restarting Wireshark, it should show you two new interfaces in the interface selection:

* Inspektor Gadget (Daemon): use this, if you're running `ig daemon`
* Inspektor Gadget on Kubernetes: use this, if you're running ig installed on your Kubernetes cluster
