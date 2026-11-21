# Emudhroll

Unenrollment using the compromised eMudhra intermediate CA certificates to intercept and spoof ChromeOS device management requests. Only works on ChromeOS versions 152 and below.

# Setup

1. Clone the repo:
   `git clone https://github.com/SPIRAME/Emudhroll && cd Emudhroll`
2. Install requirements:
   `pip install -r requirements.txt`
3. Run the proxy server:
   `python main.py [-e] [-p] [-v] [-P <port>]`

The proxy listens on port `8080` by default.

# Instructions

1. Powerwash the Chromebook.
2. On the welcome screen, open the quick settings tray in the bottom right corner, connect to Wi-Fi, and open the network's proxy settings from the same tray.
3. Select **Manual proxy configuration**.
4. Enable **Use the same proxy for all protocols**.
5. Enter your computer's local IP address and port `8080`.
6. Continue through setup as normal and it should unenrolol. It is necessary to do this as fast as possible, as revocation will occur if not done fast enough and you will have to powerwash and try again.

# Re-enrollment

If you previously unenrolled using permanent mode and still have your DMToken backup saved (saved to `dmtoken.txt` in the directory you ran the script from), it is possible to temporarily re-enroll on versions 152 and below after the patch.

The instructions to use are the same as normal, just pass the `-e` argument to `main.py`

> [!CAUTION]
> Due to the serverside changes, this will not persist after a powerwash.

# Troubleshooting

**"Can't reach Google" error:** If the Chromebook is on version 152 or below, this indicates the compromised eMudhra certificates have been revoked and are no longer trusted by the client. You will need to powerwash and try again.

**Chromebook not connecting to the proxy:** If no requests are being logged in verbose mode (`-v`), this is a firewall issue on the host side blocking incoming connections. Powerwashing will not help, as the issue will need to be resolved on the host side.

> [!WARNING]
> You must powerwash and try again for every failed attempt as there is a 99% chance that you got revoked.

# Credits

1. Lxrd for getting the unenrollment to work using the compromised eMudhra CA certificates
2. Katie for improving the scripts
3. eMudhra for being incompetent and even allowing this to happen

[Join the Discord](https://discord.gg/d3B2FtxrpF)
