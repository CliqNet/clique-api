# app/services/email.py
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content
from jinja2 import Environment, FileSystemLoader
import asyncio
from concurrent.futures import ThreadPoolExecutor
from app.core.config import settings
# import os


class EmailService:
    def __init__(self):
        self.sg = sendgrid.SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)
        self.from_email = settings.FROM_EMAIL
        self.executor = ThreadPoolExecutor(max_workers=5)

        # Setup Jinja2 for email templates
        self.env = Environment(loader=FileSystemLoader("app/templates/email"))

    def _send_email_sync(
        self, to_email: str, subject: str, html_content: str, text_content: str = None
    ):
        """Synchronous email sending via SendGrid API"""
        try:
            from_email = Email(self.from_email)
            to_email = To(to_email)

            # Create mail object
            mail = Mail(
                from_email=from_email,
                to_emails=to_email,
                subject=subject,
                html_content=Content("text/html", html_content),
            )

            # Add plain text version if provided
            if text_content:
                mail.add_content(Content("text/plain", text_content))

            # Send email
            response = self.sg.send(mail)

            if response.status_code in [200, 201, 202]:
                return True
            else:
                print(f"SendGrid API error: {response.status_code} - {response.body}")
                return False

        except Exception as e:
            print(f"Email sending failed: {e}")
            return False

    async def send_email(
        self, to_email: str, subject: str, template: str, context: dict
    ):
        """Asynchronous email sending"""
        try:
            template_obj = self.env.get_template(f"{template}.html")
            html_content = template_obj.render(**context)

            # Try to get text template as well
            text_content = None
            try:
                text_template = self.env.get_template(f"{template}.txt")
                text_content = text_template.render(**context)
            except:
                pass  # Text template is optional

            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self.executor,
                self._send_email_sync,
                to_email,
                subject,
                html_content,
                text_content,
            )
        except Exception as e:
            print(f"Email template rendering failed: {e}")
            return False

    async def send_password_reset_email(self, email: str, reset_token: str):
        """Send password reset email"""
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"

        return await self.send_email(
            to_email=email,
            subject="Password Reset Request",
            template="password_reset",
            context={"reset_url": reset_url, "expires_in": "1 hour"},
        )

    async def send_verification_email(self, email: str, verification_token: str):
        """Send email verification"""
        verify_url = f"{settings.FRONTEND_URL}/verify-email?token={verification_token}"

        return await self.send_email(
            to_email=email,
            subject="Verify Your Email",
            template="email_verification",
            context={"verify_url": verify_url},
        )


email_service = EmailService()
