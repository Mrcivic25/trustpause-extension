# TrustPause Extension

Welcome to the open-source repository for the TrustPause Browser Extension! 

TrustPause is a privacy-first browser extension designed to protect users—especially vulnerable individuals like seniors—from phishing, tech support scams, and malicious domains.

## Overview
This repository contains the Manifest V3 client-side code for the extension. It handles:
- **UI & Interstitials:** The warning screens, popups, and history views.
- **Client-Side Protections:** Form-field detection, tracking parameter stripping, and tech-support scam dialog bombing prevention.
- **Visual Hashing:** Safely computes perceptual hashes of the screen locally without sending images to the server.

### Backend Infrastructure
To protect our proprietary threat intelligence, lookalike brand logic, and perceptual hash reference sets, the backend API and scoring logic are **closed source**. The extension communicates securely with the `trustpause-api` backend to receive final verdicts on domain safety.

## Local Development

To load the extension locally for testing or development:
1. Clone this repository.
2. Open Chrome/Edge and go to `chrome://extensions/`.
3. Enable **Developer mode** in the top right.
4. Click **Load unpacked** and select the root directory of this repository.

## Legal
- [Privacy Policy](https://trustpause.app/privacy)
- [Terms of Service](https://trustpause.app/terms)

Thank you for helping us keep the web safe!
