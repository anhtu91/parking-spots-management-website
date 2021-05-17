import smtplib
import os

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


subject = "Registration Confirmation - Parking spots management system"
body = "You have registered by Parking spots management system. In attachment are MQTT Certificate for securing MQTT Connection by Owntracks"
server = "smtp.gmail.com"
sender_email = "tuoithantienchukodien@gmail.com"
receiver_email = "anhtu91@gmail.com"
password = "01672280954"


# Create a multipart message and set headers
message = MIMEMultipart()
message["From"] = sender_email
message["To"] = receiver_email
message["Subject"] = subject
message["Bcc"] = receiver_email  # Recommended for mass emails

# Add body to email
message.attach(MIMEText(body, "plain"))

files_path = [os.path.dirname(os.path.abspath(__file__))+'/mqtt_client_key/ca.pem', os.path.dirname(os.path.abspath(__file__))+'/mqtt_client_key/ca.key']

for file_path in files_path:
    with open(file_path, "rb") as attachment:
        part = MIMEBase('application', "octet-stream")
        part.set_payload((attachment).read())
        # Encoding payload is necessary if encoded (compressed) file has to be attached.
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', "attachment; filename= %s" % os.path.basename(file_path))
        message.attach(part)


# Start SMTP server at port 587
server = smtplib.SMTP(server, 587)
server.starttls()
# Enter login credentials for the email you want to sent mail from
server.login(sender_email, password)
text = message.as_string()
# Send mail
server.sendmail(sender_email, receiver_email, text)

server.quit()