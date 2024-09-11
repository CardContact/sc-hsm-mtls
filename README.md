# sc-hsm-mtls
A Java example showing how to connect with mTLS to a remote host with client authentication
using a certificate on the SmartCard-HSM.

To test this, get a certificate to access the [CardContact Developers Network](https://www.smartcard-hsm.com/cdn.html#cdn).

This demo will connect to https://cdn.cardcontact.de, which requires client authentication using
a DevNet-CA certificate.

This demo uses OCF, the sc-hsm-jceprovider and Bouncycastle. It is a pure Java implementation
without the need to install a PKCS#11 module.

The demo assumes that the demo PIN 648219 is set on the SmartCard-HSM.
