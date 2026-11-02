# Setup

1. Clone the repo:
   git clone https://github.com/SPIRAME/Emudhroll && cd Emudhroll
2. Install requirements:
   pip install -r requirements.txt
3. Run the proxy:
   python main.py
4. Permanent unenrollment mode:
   python main.py --permanent
5. Re-enroll:
   python main.py --enroll

The proxy listens on port 8080.

## Chromebook setup (normal unenroll)

1. Powerwash the Chromebook.
2. On the Welcome OOBE screen, connect to Wi-Fi from the bottom right quick settings tray and open its proxy settings from there as well. (it is necessary to do it on the welcome as revocation will occur otherwise if not done fast enough)
3. Set to Manual proxy configuration.
4. Enable Use the same proxy for all protocols.
5. Enter your computer's IP and port 8080.
6. Continue through OOBE and it should unenrolol
7. **Note:** If you see a "can't reach Google" error and the Chromebook is on version 152 or below, powerwash and try again (this indicates revocation occurred and the client no longer trusts the eMudhra cert). Another edge case is the Chromebook not actually connecting to the proxy due to firewall issues on the host (indicative of no requests being logged in verbose mode), powerwashing will not help in this case as the issue would need to be resolved on the host side.

## Permanent unenrollment (--permanent)

1. Start the proxy: python main.py --permanent
2. Go through OOBE on the Chromebook.
3. Powerwash the device after the proxy says it unenrolled
4. Once powerwashed, It will successfully unenrollol
5. **Note:** If your school has disabled the device you can't do the permanent method and must do the temp method.

## Re-enroll (--enroll)

1. Run: python main.py --enroll
2. Enter the stable device secret (hex) when prompted (this is obtained via entering devmode and running vpd -l as root in vt2)
3. On powerwash, it will successfully reenroll

## Credits

1. Lxrd for for getting the unenrollment to work using the Emudhra CA Compromise
2. Katie for improving the scripts
3. Emudhra thank you for your incompetency

[Join the Discord](https://discord.gg/d3B2FtxrpF)
