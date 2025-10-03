"""
Email Service for sending verification emails
"""

import asyncio
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional
from ..core.config import settings

class EmailService:
    def __init__(self):
        self.smtp_host = getattr(settings, 'SMTP_HOST', None)
        self.smtp_port = getattr(settings, 'SMTP_PORT', 587)
        self.smtp_username = getattr(settings, 'SMTP_USERNAME', None)
        self.smtp_password = getattr(settings, 'SMTP_PASSWORD', None)
        self.from_email = getattr(settings, 'FROM_EMAIL', self.smtp_username)
        
    def is_configured(self) -> bool:
        """Check if email service is properly configured"""
        return all([
            self.smtp_host,
            self.smtp_port,
            self.smtp_username,
            self.smtp_password
        ])
        
    def generate_otp(self, length: int = 6) -> str:
        """Generate a random OTP"""
        return ''.join(random.choices(string.digits, k=length))
        
    async def send_verification_email(self, email: str, otp: str, username: str) -> bool:
        """Send verification email with OTP"""
        if not self.is_configured():
            print("Email service not configured, skipping email send")
            return True  # Return True in development when email is not configured
            
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = email
            msg['Subject'] = f"Verify your email - {settings.APP_NAME}"
            
            # Email body
            body = f"""
            Hi {username},
            
            Thank you for registering with {settings.APP_NAME}!
            
            To complete your registration, please verify your email address using the following OTP:
            
            Verification Code: {otp}
            
            This code will expire in 15 minutes.
            
            If you didn't create an account with us, please ignore this email.
            
            Best regards,
            {settings.APP_NAME} Team
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            await self._send_email_async(msg)
            return True
            
        except Exception as e:
            print(f"Error sending verification email: {str(e)}")
            return False
            
    async def _send_email_async(self, msg: MIMEMultipart):
        """Send email asynchronously"""
        def send_email():
            try:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                text = msg.as_string()
                server.sendmail(self.from_email, msg['To'], text)
                server.quit()
            except Exception as e:
                print(f"SMTP Error: {str(e)}")
                raise
                
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, send_email)

# Global email service instance
email_service = EmailService()