# utils.py
import os
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from openai import OpenAI
from flask import current_app

# Initialize OpenAI client (will be overridden by app context if needed)
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))


def send_otp_email(to_email: str, otp: str) -> bool:
    """
    Send OTP to user's email via SMTP.

    Args:
        to_email (str): Recipient email address
        otp (str): One-time password to send

    Returns:
        bool: True if sent successfully, False otherwise
    """
    sender_email = os.getenv("MAIL_USERNAME")
    sender_password = os.getenv("MAIL_PASSWORD")
    smtp_server = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("MAIL_PORT", 587))

    if not sender_email or not sender_password:
        print("❌ Mail credentials missing in environment: MAIL_USERNAME or MAIL_PASSWORD")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your OTP for PromptArena"
    msg["From"] = sender_email
    msg["To"] = to_email

    # Use plain hyphen '-' instead of en-dash '–' to avoid encoding issues
    text_body = f"""
Hello,

Your one-time password (OTP) is: {otp}

This code expires in 5 minutes.

Welcome to PromptArena - Where Words Battle!
    """.strip()

    html_body = f"""
    <html>
      <body>
        <p>Hello,</p>
        <p>Your one-time password (OTP) is:</p>
        <h2>{otp}</h2>
        <p><strong>This code will expire in 5 minutes.</strong></p>
        <p>Welcome to <strong>PromptArena</strong> - Where Words Battle!</p>
      </body>
    </html>
    """.strip()

    # ✅ CRITICAL: Encode as UTF-8 explicitly
    part1 = MIMEText(text_body, "plain", "utf-8")
    part2 = MIMEText(html_body, "html", "utf-8")

    msg.attach(part1)
    msg.attach(part2)

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            # ✅ Encode entire message as UTF-8 before sending
            server.sendmail(sender_email, to_email, msg.as_string().encode('utf-8'))
        print(f"✅ OTP email sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Failed to send OTP email: {e}")
        return False

def evaluate_prompt_with_ai(user_prompt: str, level: str = "Basic") -> dict:
    """
    Evaluate user prompt using OpenAI GPT model.

    Returns:
        dict: Evaluation scores and feedback
    """
    try:
        # Use app context client if available, else fallback
        _client = getattr(current_app, 'extensions', {}).get('openai_client', client)

        prompt_instruction = f"""
You are a fair and strict judge in a prompt battle arena.
Evaluate the following user-generated prompt based on three criteria: Creativity, Relevance, and Clarity.
The prompt was submitted for the '{level}' level.

User Prompt: "{user_prompt}"

Respond in **strict JSON format only**:
{{
  "creativity": <score out of 10>,
  "relevance": <score out of 10>,
  "clarity": <score out of 10>,
  "overall": <average of the three>,
  "feedback": "<2-sentence constructive feedback>"
}}

Do not include any extra text before or after the JSON.
        """

        response = _client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful AI judge for a prompt battle."},
                {"role": "user", "content": prompt_instruction}
            ],
            max_tokens=256,
            temperature=0.7
        )

        result = response.choices[0].message.content.strip()
        evaluation = json.loads(result)
        return evaluation

    except Exception as e:
        print("OpenAI API Error:", str(e))
        return {
            "creativity": 0,
            "relevance": 0,
            "clarity": 0,
            "overall": 0,
            "feedback": "Evaluation failed due to an error. Please try again."
        }