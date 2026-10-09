# Google Cloud OAuth 2.0 Free Setup Guide for YouTube Automation

Setting up your own Google Cloud project is 100% free and provides a dedicated daily quota of **10,000 units/day** direct from Google, with zero third-party data sharing.

---

## Step 1: Create a Google Cloud Project

1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Click **Select a project** > **New Project**.
3. Name your project (for example: `youtube-antigravity-automation`) and click **Create**.

---

## Step 2: Enable the YouTube Data API v3

1. In the Google Cloud Console, open the navigation menu and go to **APIs & Services** > **Library**.
2. Search for **YouTube Data API v3**.
3. Click on it and select **Enable**.

---

## Step 3: Configure the OAuth Consent Screen

1. Go to **APIs & Services** > **OAuth consent screen**.
2. Choose **External** user type and click **Create**.
3. Fill in the required fields:
   - **App name:** `Antigravity YouTube Manager`
   - **User support email:** Your email address.
   - **Developer contact information:** Your email address.
4. Click **Save and Continue**.
5. **Scopes:** Click **Add or Remove Scopes**, then search for and add:
   - `https://www.googleapis.com/auth/youtube.upload`
   - `https://www.googleapis.com/auth/youtube.force-ssl`
   - `https://www.googleapis.com/auth/youtube.readonly`
6. Click **Save and Continue**.
7. **Test Users:** Under **Test users**, click **Add Users** and add your own Google email address (the owner of the YouTube channel).
8. Click **Save and Continue**.

---

## Step 4: Create OAuth 2.0 Client ID Credentials

1. Go to **APIs & Services** > **Credentials**.
2. Click **Create Credentials** > **OAuth client ID**.
3. Under **Application type**, select **Desktop app**.
4. Name it `Antigravity CLI Client`.
5. Click **Create**.
6. A dialog will appear with your credentials. Click **Download JSON**.
7. Store the file securely and configure the environment variables:
   - Set `YOUTUBE_CLIENT_SECRETS_FILE` to the path of your downloaded JSON file.
   - Set `YOUTUBE_TOKEN_FILE` to your desired token cache path.

---

## Step 5: One-Time Local Authorization Flow

Run the initial login command to authorize:
```bash
python3 -c "
import youtube_safe_mcp
youtube_safe_mcp.get_youtube_client()
print('Authorization successful!')
"
```
A browser window will open automatically asking you to log in to your Google account and grant permissions. Once approved, your OAuth token will be refreshed automatically.
