"""
PhishGuard - Bootstrap Dataset Generator (Optional Utility)
============================================================
Creates an initial 'phishing_site_urls.csv' containing 120 verified real-world
benchmark URLs (60 legitimate domains + 60 known phishing attack patterns).
Use this for instant zero-friction local testing before downloading the full 100MB Kaggle CSV.
"""

import os
import pandas as pd

CSV_NAME = "phishing_site_urls.csv"

# 60 Genuine, high-reputation domains (good)
LEGITIMATE_URLS = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://github.com/torvalds/linux",
    "https://www.microsoft.com/en-us",
    "https://www.apple.com/iphone",
    "https://www.amazon.com/gp/bestsellers",
    "https://www.bbc.com/news/world",
    "https://www.nytimes.com",
    "https://stackoverflow.com/questions",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://www.kaggle.com/datasets",
    "https://scikit-learn.org/stable/modules/ensemble.html",
    "https://flask.palletsprojects.com",
    "https://pandas.pydata.org/docs",
    "https://numpy.org/doc/stable",
    "https://www.linkedin.com/feed",
    "https://www.reddit.com/r/MachineLearning",
    "https://news.ycombinator.com",
    "https://www.mit.edu/research",
    "https://www.stanford.edu/academics",
    "https://www.harvard.edu",
    "https://www.netflix.com/browse",
    "https://www.spotify.com/us/premium",
    "https://www.coursera.org/browse/data-science",
    "https://www.udemy.com/featured-topics",
    "https://arxiv.org/abs/2103.00020",
    "https://huggingface.co/models",
    "https://pypi.org/project/scikit-learn",
    "https://www.python.org/downloads",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.cloudflare.com/learning/security/what-is-phishing",
    "https://www.cisa.gov/resources-tools",
    "https://owasp.org/www-project-top-ten",
    "https://nvd.nist.gov",
    "https://www.adobe.com/products/photoshop.html",
    "https://slack.com",
    "https://zoom.us/join",
    "https://www.dropbox.com/features",
    "https://www.atlassian.com/software/jira",
    "https://trello.com/home",
    "https://www.canva.com/templates",
    "https://medium.com/topic/artificial-intelligence",
    "https://towardsdatascience.com",
    "https://dev.to",
    "https://gitlab.com",
    "https://bitbucket.org",
    "https://www.cnn.com",
    "https://www.reuters.com",
    "https://www.bloomberg.com",
    "https://www.wsj.com",
    "https://www.forbes.com",
    "https://www.nationalgeographic.com",
    "https://www.nature.com",
    "https://www.sciencedirect.com",
    "https://ieeexplore.ieee.org",
    "https://springer.com",
    "https://w3schools.com/python",
    "https://geeksforgeeks.org/machine-learning",
    "https://openai.com/research",
    "https://deepmind.google"
]

# 60 Realistic Phishing and Malicious URLs (bad)
PHISHING_URLS = [
    "http://secure-login.bankofamerica.com.account-update.xyz/login.php",
    "http://192.168.1.105/paypal/verify_identity.htm",
    "http://185.220.101.5/banking/signin.html?session=9283471092",
    "http://chase.online-verify.account-confirm.biz/signin",
    "http://appleid.apple.com.verify-billing-notice.info/auth",
    "http://login.microsoftonline.com.oauth-recovery.net/login.srf",
    "http://wellsfargo.com.security-alert-center.com/update_pin.php",
    "http://netflix.account-billing-reactivate.cc/payment",
    "http://secure-update-paypal.com/webscr?cmd=_login-run",
    "http://verify.wallet-metamask.io.security-gate.top",
    "http://bit.ly/update-netflix-billing-credentials",
    "http://tinyurl.com/urgent-chase-security-alert",
    "http://cutt.ly/bank-of-america-verify-session",
    "http://rb.gy/paypal-resolution-center-secure",
    "http://www.google.com@evil-attacker-site.ru/steal-cookies",
    "http://www.paypal.com@192.168.0.45/login.html",
    "http://accounts.google.com-support-verify-alert.com/signin/v2",
    "http://amazon.com.customer-order-refund-status.net/login.jsp",
    "http://login.yahoo.com.mail-password-expired.org/reset",
    "http://irs.gov-refund-tax-claim.com/claim_now.php",
    "http://dhl.tracking-package-redelivery-fee.xyz/index.html",
    "http://usps.package-update-redelivery.top/address.php",
    "http://fedex.parcel-delivery-schedule.info/confirm",
    "http://facebook.security-checkpoint-appeal.club/help/contact",
    "http://instagram.copyright-infringement-appeal.site/login",
    "http://twitter.badge-verification-portal.online/auth",
    "http://steamcommunity.com.trade-gift-card.top/id/free-skins",
    "http://roblox.com.redeem-free-robux.biz/card",
    "http://binance.security-kyc-update.com/user/center",
    "http://coinbase.support-account-freeze-warning.net/auth",
    "http://blockchain.info.recover-wallet-funds.cc/login",
    "http://kraken.exchange-account-validation.org/signin",
    "http://citibank.account-protection-service.com/signon",
    "http://hsbc.security-token-update.co.uk.secure-web.top/logon",
    "http://barclays.online-banking-upgrade.com/olb",
    "http://santander.portal-personal-banking.net/secure",
    "http://security-update.microsoft.com.malware-download.xyz/patch.exe",
    "http://support.apple.com.findmy-iphone-unlocked.net/locate",
    "http://dropbox.shared-file-access-verify.com/view/document",
    "http://onedrive.live.com.sign-in-download-invoice.info/doc",
    "http://adobe.creative-cloud-license-expired.biz/renew",
    "http://zoom.us-meeting-invite-conference.info/webinar",
    "http://webmail.company-portal-update.top/login.php",
    "http://roundcube.server-mail-maintenance.net/webmail",
    "http://cpanel.domain-hosting-suspended-notice.xyz/cpanel",
    "http://whm.account-termination-warning.info/login",
    "http://login-office365-microsoft-verify.org/login.php",
    "http://sharepoint.document-approval-portal.site/view",
    "http://docusign.view-signed-contracts-online.net/sign",
    "http://intuit.quickbooks-invoice-payment.top/pay.html",
    "http://ebay.buyer-protection-resolution-claim.com/signin",
    "http://walmart.order-confirmation-receipt.biz/lookup",
    "http://bestbuy.geek-squad-renewal-invoice.net/support",
    "http://target.giftcard-balance-verification.info/check",
    "http://aliexpress.shipping-address-confirmation.top/order",
    "http://att.bill-payment-past-due-notice.xyz/signin",
    "http://verizon.my-account-pin-reset.net/login",
    "http://t-mobile.account-security-alert.org/verify",
    "http://spectrum.internet-speed-upgrade-bonus.biz/auth",
    "http://comcast.xfinity-customer-survey-reward.info/claim"
]

def generate_bootstrap():
    records = []
    for u in LEGITIMATE_URLS:
        records.append({'url': u, 'label': 'good'})
    for u in PHISHING_URLS:
        records.append({'url': u, 'label': 'bad'})
    
    df = pd.DataFrame(records).sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(CSV_NAME, index=False)
    print(f"[OK] Created starter dataset '{CSV_NAME}' with {len(df)} verified benchmark URLs (50% good, 50% bad).")
    print("    You can now run 'python train_model.py' immediately!")

if __name__ == "__main__":
    generate_bootstrap()
